#!/bin/bash

HOME_DIR="/home/ubuntu"
MACHINE_INVENTORY="${HOME_DIR}/machine.txt"
CLUSTER_NAME="kubernetes-the-hard-way"
K8S_API_SERVER="https://127.0.0.1"
K8S_API_SERVER_PORT=6443
CURRENT_HOSTNAME=$(hostname)

#==========================#
#   Function Definitions   #
#==========================#
install_dependencies () {
    echo "[BASE] Running base installation with user - $(whoami) in location $PWD..."
    apt-get update
    echo "[BASE] Installing dependencies..."
    apt-get -y install wget curl vim openssl git bash-completion ca-certificates gnupg net-tools
    echo "[BASE] Cloning Kubernetes the Hard Way..."
    mkdir kubernetes && cd "${HOME_DIR}"/kubernetes
    git clone --depth 1 https://github.com/taravinth23/kubernetes-the-hard-way.git
    pushd "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way &>/dev/null
    ARCH=$(dpkg --print-architecture)
    echo "[BASE] Display downloading dependencies..."
    cat downloads-${ARCH}.txt
    echo "[BASE] Downloading dependencies..."
    wget -q --show-progress --https-only --timestamping -P downloads -i downloads-${ARCH}.txt
    echo "[BASE] Untar contents -> specific folders..."
    mkdir -p downloads/{client,cni-plugins,controller,worker}
    tar -xvf downloads/crictl-v1.32.0-linux-${ARCH}.tar.gz -C downloads/worker/
    tar -xvf downloads/containerd-2.1.0-beta.0-linux-${ARCH}.tar.gz --strip-components 1 -C downloads/worker/
    tar -xvf downloads/cni-plugins-linux-${ARCH}-v1.6.2.tgz -C downloads/cni-plugins/
    tar -xvf downloads/etcd-v3.6.0-rc.3-linux-${ARCH}.tar.gz -C downloads/ --strip-components 1 etcd-v3.6.0-rc.3-linux-${ARCH}/etcdctl etcd-v3.6.0-rc.3-linux-${ARCH}/etcd
    echo "[BASE] Move download to respective folders..."
    mv downloads/{etcdctl,kubectl} downloads/client/
    mv downloads/{etcd,kube-apiserver,kube-controller-manager,kube-scheduler} downloads/controller/
    mv downloads/{kubelet,kube-proxy} downloads/worker/
    mv downloads/runc.${ARCH} downloads/worker/runc
    echo "[BASE] Remove downloaded files..."
    rm -rf downloads/*gz
    echo "[BASE] Setting execute permissions..."
    chmod +x downloads/{client,cni-plugins,controller,worker}/*
    echo "[BASE] Copy kubectl to /usr/local/bin..."
    cp downloads/client/kubectl /usr/local/bin/
    echo "[BASE] Kubectl version..."
    kubectl version --client
    echo "[BASE] Enable SSH & root login..."
    systemctl enable ssh && systemctl start ssh
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    popd &>/dev/null
    pushd /root &>/dev/null
    echo "[BASE] Generating SSH key..."
    ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N "" -q
    cat /root/.ssh/id_ed25519.pub
    popd &>/dev/null
    echo "[BASE] copy public key to ${HOME_DIR}/sshkey.pub..."
    cp /root/.ssh/id_ed25519.pub "${HOME_DIR}"/sshkey.pub
    echo "[BASE] Checking for file ${MACHINE_INVENTORY}..."
    pushd /home/ubuntu &>/dev/null
    if [ -f "${MACHINE_INVENTORY}" ]; then
        echo "[BASE] Updating /etc/hosts file..."
        CURRENT_HOSTNAME=$(hostname -I | awk '{print $1}')
        while read IP FQDN HOSTNAME SUBNET HOST; do
            echo "RUNNING FOR ${IP} ===> ${HOST}"
            if [[ "${HOSTNAME}" == "${CURRENT_HOSTNAME}" ]]; then
                # If IP matches, replace line with updated hostname and FQDN
                echo "[BASE] Updating /etc/hosts for current host ${HOST}..."
                sed -i "s/^127\.0\.0\.1\s\+localhost.*/127.0.0.1 ${HOST} ${FQDN} localhost/" /etc/hosts
                echo "[BASE] Setting hostname..."
                hostnamectl set-hostname ${HOST}
                echo "[BASE] Reloading systemd manager configuration..."
                systemctl daemon-reload
                echo "[BASE] Restarting systemd-hostnamed..."
                systemctl restart systemd-hostnamed
            else
                # If IP does not match, append IP, FQDN, HOST at the end of /etc/hosts if not already present
                if ! grep -q "$IP" /etc/hosts; then
                    echo "${IP} ${FQDN} ${HOST}" >> /etc/hosts
                fi
                echo "[Base][Manual-Setup] Copy the current machine ssh-key to root@${HOST}:/root/.ssh/authorized_keys"
                echo "[Base][Manual-Setup] scp ${HOME_DIR}/sshkey.pub root@${HOST}:/root/.ssh/$(hostname).pub"
            fi
        done < "${MACHINE_INVENTORY}"
        echo "[BASE] Updated /etc/hosts file:"
        echo "************************************************************************"
        cat "${HOME_DIR}"/sshkey.pub
        echo "************************************************************************"
    else
        echo "[BASE] File ${MACHINE_INVENTORY} not found. Skipping /etc/hosts update."
    fi
    popd &>/dev/null
    echo "[BASE] Base installation completed."
    

}

certificate_installation() {
    echo "[CERTIFICATE] Running certificate installation..."
    if [[ "server" == "${CURRENT_HOSTNAME}" ]]; then

        echo "[CERTIFICATE] Setting up Root CA certificate authority (CA)..."
        pushd "${HOME_DIR}"/kubernetes &>/dev/null
        mkdir CERT
        echo "[CERTIFICATE] Copy ca.conf to ${HOME_DIR}/kubernetes/CERT..."
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/ca.conf "${HOME_DIR}"/kubernetes/CERT
        popd &>/dev/null

        pushd "${HOME_DIR}"/kubernetes/CERT &>/dev/null
        echo "************** [CERTIFICATE] Creating the Root CA certificate **************"
        echo "[CERTIFICATE] A file called ca.key is created, containing the private key used by the Root CA."
        openssl genrsa -out ca.key 4096
        # ✔ This command generates a new RSA private key.
        # ✔ This creates a private key file named ca.key.
        # ✔ It's used by the Root Certificate Authority (CA) to sign other certificates.
        # ✔ The key size is 4096 bits — meaning it's very secure.
        # genrsa: This tells OpenSSL to create an RSA private key.
        # -out ca.key: The output file where the private key will be saved.
        # 4096: The size of the key in bits (4096 bits – very secure).
        echo "[CERTIFICATE] let's generates a self-signed X.509 certificate for the Root CA which is valid for 10 years (3653 days)..."
        echo "[CERTIFICATE] The certificate is saved in a file named ca.crt."
        echo "[CERTIFICATE] The certificate is created using the private key in ca.key and the configuration in (like name, location, etc.) ca.conf."
        openssl req -x509 -new -sha512 -noenc -key ca.key -days 3653 -config ca.conf -out ca.crt
        # req: This is the OpenSSL tool for creating and processing certificate requests and certificates.
        # -x509: Creates a self-signed certificate instead of a certificate request.
        # -new: Indicates that a new certificate is being generated.
        # -sha512: Uses the SHA-512 hash function for the certificate's signature (very secure).
        # -noenc: Specifies that the private key is not encrypted (optional in some setups).
        # -key ca.key: The private key (ca.key) used to sign the certificate.
        # -days 3653: The certificate will be valid for 3653 days (~10 years).
        # -config ca.conf: Uses the ca.conf configuration file for certificate details like distinguished name, extensions, etc.
        # -out ca.crt: Writes the final certificate to ca.crt.
        ls *.crt *.key *.conf
        for host in node-0 node-1; do
            echo "[CERTIFICATE] Creating directory on ${host}..."
            ssh root@${host} mkdir -p "${HOME_DIR}"/kubernetes/CERT
            echo "[CERTIFICATE] Copying ca.conf, ca.key and ca.crt to ${host}..."
            scp ca.conf ca.key ca.crt root@${host}:"${HOME_DIR}"/kubernetes/CERT
        done
        popd &>/dev/null
    fi

    echo "[CERTIFICATE] Creating certificates for Kubernetes components..."
    pushd "${HOME_DIR}"/kubernetes/CERT &>/dev/null
    certs=(
        "admin" "node-0" "node-1"
        "kube-proxy" "kube-scheduler"
        "kube-controller-manager"
        "kube-api-server"
        "service-accounts"
    )
    echo "[CERTIFICATE] Generating certificates for: ${certs[*]}"
    for i in ${certs[*]}; do
        echo "[CERTIFICATE] Create the component's private key for ${i}..."
        openssl genrsa -out "${i}.key" 4096
        echo "[CERTIFICATE] Create the certificate signing request (CSR) for ${i}..."
        openssl req -new -key "${i}.key" -sha256 -config "ca.conf" -section ${i} -out "${i}.csr"
        echo "[CERTIFICATE] The certificate signing request is created using the private key in ${i}.key and the configuration in ca.conf."
        echo "[CERTIFICATE] Sign the CSR and create the final certificate..."
        openssl x509 -req -days 3653 -in "${i}.csr" -copy_extensions copyall -sha256 -CA "ca.crt" -CAkey "ca.key" -CAcreateserial -out "${i}.crt"
        echo "[CERTIFICATE] Sign the certificate using the CA (ca.crt and ca.key) for ${i}..."
        echo "[CERTIFICATE] The final certificate is saved in ${i}.crt and is valid for 10 years (3653 days)."
        echo "[CERTIFICATE] -CAcreateserial: It creates a serial number for the certificate. If a serial number file (ca.srl) already exists, it will be used instead."
        echo "[CERTIFICATE] -copy_extensions copyall: This option copies all X.509 extensions from the CSR to the signed certificate. This is important for preserving any special attributes or constraints specified in the CSR, such as Subject Alternative Names (SANs), key usage, and extended key usage. By using this option, you ensure that the signed certificate retains the same properties as requested in the CSR, which is often necessary for the certificate to function correctly in its intended role."
        echo "[CERTIFICATE] -sha256: This specifies that the SHA-256 hashing algorithm should be used for signing the certificate. SHA-256 is a widely used and secure hashing algorithm that provides a good balance between security and performance."
        ls -l ${i}.key ${i}.csr ${i}.crt
    done

    ls -1 *.crt *.key *.csr
    
    if [[ "server" == "${CURRENT_HOSTNAME}" ]]; then
        echo "**************** SERVER ----> NODES ****************"
        echo "[CERTIFICATE] Running on the server host, proceeding with certificate distribution to each nodes..."
        for host in node-0 node-1; do
            echo "[CERTIFICATE] Copying to ${host}..."
            ssh root@${host} rm -rf /var/lib/kubelet
            ssh root@${host} mkdir /var/lib/kubelet
            ssh root@${host} chmod 700 /var/lib/kubelet

            echo "[CERTIFICATE] Copying ca.crt, ${host}.crt, and ${host}.key to ${host}..."
            scp ca.crt root@${host}:/var/lib/kubelet/

            scp ${host}.crt root@${host}:/var/lib/kubelet/kubelet.crt

            scp ${host}.key root@${host}:/var/lib/kubelet/kubelet.key
        done
    else
        if echo "$CURRENT_HOSTNAME" | grep -q "node"; then
            echo "**************** NODES ----> SERVER ****************"
            echo "[CERTIFICATE] Running on a worker node Copying ca.key, ca.crt, kube-api-server.key, kube-api-server.crt, service-accounts.key, and service-accounts.crt to server..."
            ssh root@server mkdir -p mkdir "${HOME_DIR}/worker_certificate_$CURRENT_HOSTNAME"
            scp ca.key ca.crt kube-api-server.key kube-api-server.crt service-accounts.key service-accounts.crt root@server:"${HOME_DIR}/worker_certificate_$CURRENT_HOSTNAME"
        else
            echo "[CERTIFICATE] Current Host Not a recognized hostname for certificate distribution. Skipping this step."
        fi
    fi
    echo "CURRENT_HOSTNAME is ${CURRENT_HOSTNAME}"
}

kubeconfig_configuration() {
    echo "[KUBECONFIG] Kubernetes Configuration Files for Authentication..."
    pushd "${HOME_DIR}"/kubernetes/CERT &>/dev/null

    echo "############################### KUBELET ###############################"
    echo "[KUBECONFIG] Lets create kubelet Kubernetes Configuration File..."
    echo "[KUBECONFIG] Kubeconfig files are created for each node (node-0 and node-1) to allow them \
    to authenticate with the Kubernetes API server using their respective certificates and keys."

    config=(
        "kube-proxy" "kube-controller-manager" "kube-scheduler" "admin"
    )

    if [[ "server" == "${CURRENT_HOSTNAME}" ]]; then
        for host in node-0 node-1; do

            echo "[KUBECONFIG] Setting up cluster information in the kubeconfig for ${host}..."
            echo "[KUBECONFIG] API Server is ${K8S_API_SERVER} and Port is ${K8S_API_SERVER_PORT}"
            echo "[KUBECONFIG] Kubeconfig file is ${host}.kubeconfig ..."

            kubectl config set-cluster "${CLUSTER_NAME}" --certificate-authority=ca.crt --embed-certs=true \
                --server="${K8S_API_SERVER}:${K8S_API_SERVER_PORT}" --kubeconfig=${host}.kubeconfig
            # Sets the cluster information in the kubeconfig file for the specified host with the given cluster name, \
            #   certificate authority, server address, and kubeconfig file.
            # kubectl config set-cluster: This command is used to define a cluster in a kubeconfig file.
            # "${CLUSTER_NAME}": This is a variable that holds the name of the Kubernetes cluster. It is used to identify the cluster in \
            #   the kubeconfig file.
            # --certificate-authority=ca.crt: It specifies the certificate authority file (ca.crt) used to verify the API server's certificate.
            # --embed-certs=true: It embeds the certificate contents into the kubeconfig file rather than referencing the file externally.
            # --server=${K8S_API_SERVER}:${K8S_API_SERVER_PORT}: This option specifies the URL of the Kubernetes API server. \
            #   In this case, it is set to the value of the K8S_API_SERVER variable (e.g., server.kubernetes.local) and the port \
            #   specified by K8S_API_SERVER_PORT (e.g., 6443).
            # --kubeconfig=${host}.kubeconfig: This option specifies the path to the kubeconfig file \
            #   where the cluster information will be stored. The kubeconfig file is named based on the current host (e.g., node-0.kubeconfig).

            echo "[KUBECONFIG] Setting up user credentials in the kubeconfig for ${host}..."
            echo "[KUBECONFIG] User is system:node:${host} ..."
            echo "[KUBECONFIG] lets us allows the node to authenticate using its certificate and key..."

            kubectl config set-credentials system:node:${host} --client-certificate=${host}.crt --client-key=${host}.key \
                --embed-certs=true --kubeconfig=${host}.kubeconfig
            # Sets the user credentials in the kubeconfig file for the specified host with the given user name, \
            #   client certificate, client key, and kubeconfig file.
            # kubectl config set-credentials: This command is used to define user credentials in a kubeconfig file.
            # system:node:${host}: This is a variable that holds the user name for the Kubernetes node. \
            #   It is typically in the format system:node:<node-name>, where <node-name> is the name of the node.
            # --client-certificate=${host}.crt: The node’s certificate.
            # --client-key=${host}.key: The node’s private key.
            # --embed-certs=true: It embeds the certificate into the kubeconfig file.
            # --kubeconfig=${host}.kubeconfig: Writes this into the appropriate kubeconfig file.

            echo "[KUBECONFIG] Setting up context in the kubeconfig for ${host}..."
            echo "[KUBECONFIG] Context links the cluster and user together & defining how kubectl should interact..."

            kubectl config set-context default \
                --cluster="${CLUSTER_NAME}" --user=system:node:${host} --kubeconfig=${host}.kubeconfig
            # Sets the context in the kubeconfig file for the specified host with the given cluster name, user name, and kubeconfig file.
            # kubectl config set-context: This command is used to define a context in a kubeconfig file.
            # default: This is the name of the context being created. In this case, it is named "default."
            # --user=system:node:${host}: Uses the node's credentials defined earlier.

            echo "[KUBECONFIG] Setting the current context to 'default' in the kubeconfig for ${host}..."
            echo "[KUBECONFIG] This makes 'default' the active context for kubectl commands..."

            kubectl config use-context default --kubeconfig=${host}.kubeconfig
            # Sets the current context in the kubeconfig file for the specified host to "default."
            # kubectl config use-context: This command is used to set the current context in a kubeconfig file.
            # default: This is the name of the context to be set as the current context.
            # --kubeconfig=${host}.kubeconfig: This option specifies the path to the kubeconfig file where the current context will be set.
        done
        echo "[KUBECONFIG] Listing the created kubeconfig files ..."
        ls -l *.kubeconfig
    fi

    echo "[KUBECONFIG] Generating kubeconfig files : ${config[*]}"

    for service in ${config[*]}; do

        if [[ "${service}" == "admin" ]]; then
           API_SERVER_LOCAL="https://127.0.0.1"
           USER_PERMISSIONS="admin"
        else
            API_SERVER_LOCAL="$K8S_API_SERVER"
            USER_PERMISSIONS="system:${service}"
        fi
        
        echo "[KUBECONFIG] Setting up cluster information in the kubeconfig for ${service}..."
        echo "[KUBECONFIG] API Server is ${API_SERVER_LOCAL} and Port is ${K8S_API_SERVER_PORT}"

        kubectl config set-cluster "${CLUSTER_NAME}" --certificate-authority=ca.crt --embed-certs=true \
            --server="${API_SERVER_LOCAL}:${K8S_API_SERVER_PORT}" --kubeconfig="${service}".kubeconfig

        echo "[KUBECONFIG] Setting up user credentials in the kubeconfig for ${service}..."
        echo "[KUBECONFIG] User is ${USER_PERMISSIONS} ..."
        echo "[KUBECONFIG] lets us allows the ${service} to authenticate using its certificate and key..."

        kubectl config set-credentials "${USER_PERMISSIONS}" --client-certificate="${service}".crt --client-key="${service}".key \
            --embed-certs=true --kubeconfig="${service}".kubeconfig
        # Sets the user credentials in the kubeconfig file for the specified service with the given user name, \
        #   client certificate, client key, and kubeconfig file.
        # kubectl config set-credentials: This command is used to define user credentials in a kubeconfig file.
        # "${USER_PERMISSIONS}": This is a variable that holds the user name for the Kubernetes component or user.
        # --client-certificate=${service}.crt: The component's certificate.
        # --client-key=${service}.key: The component's private key.
        # --embed-certs=true: It embeds the certificate into the kubeconfig file.
        # --kubeconfig=${service}.kubeconfig: Writes this into the appropriate kubeconfig file.

        echo "[KUBECONFIG] Setting up context in the kubeconfig for ${service}..."
        echo "[KUBECONFIG] Context links the cluster and user together & defining how kubectl should interact..."

        kubectl config set-context default --cluster="${CLUSTER_NAME}" \
            --user="${USER_PERMISSIONS}" --kubeconfig="${service}".kubeconfig
        # Sets the context in the kubeconfig file for the specified service with the given cluster name, user name, and kubeconfig file.
        # kubectl config set-context: This command is used to define a context in a kubeconfig file.
        # default: This is the name of the context being created. In this case, it is named "default."
        # --cluster="${CLUSTER_NAME}": Uses the cluster defined earlier.
        # --user="${USER_PERMISSIONS}": Uses the service's credentials defined earlier.
        # --kubeconfig="${service}".kubeconfig: Writes this into the appropriate kubeconfig file.

        echo "[KUBECONFIG] Setting the current context to 'default' in the kubeconfig for ${service}..."
        echo "[KUBECONFIG] This makes 'default' the active context for kubectl commands..."

        kubectl config use-context default --kubeconfig="${service}".kubeconfig
        # Sets the current context in the kubeconfig file for the specified service to "default."
        # kubectl config use-context: This command is used to set the current context in a kubeconfig file.
        # default: This is the name of the context to be set as the current context.
        # --kubeconfig="${service}".kubeconfig: This option specifies the path to the kubeconfig file where \
        # the current context will be set.
    done

    echo "[KUBECONFIG] Listing the created kubeconfig files ..."
    ls -l *.kubeconfig

    echo "[KUBECONFIG] let's distribute the kubernetes configuration files..."
    if [[ "server" == "${CURRENT_HOSTNAME}" ]]; then
        for host in node-0 node-1; do
            echo "[KUBECONFIG] Copying server to ${host}..."
            ssh "root@${host}" "mkdir -p /var/lib/{kube-proxy,kubelet}"
            scp kube-proxy.kubeconfig "root@${host}:/var/lib/kube-proxy/kubeconfig"
            scp "${host}.kubeconfig" "root@${host}:/var/lib/kubelet/kubeconfig"

            for service in ${config[*]}; do
                echo "[KUBECONFIG] Copying ${service}.kubeconfig to ${host}..."
                scp "${service}.kubeconfig" root@${host}:"${HOME_DIR}/kubernetes/CERT/${service}.kubeconfig"
                scp "${host}.kubeconfig" root@${host}:"${HOME_DIR}/kubernetes/CERT"
            done
        done
    else
        if echo "$CURRENT_HOSTNAME" | grep -q "node"; then
            scp admin.kubeconfig kube-controller-manager.kubeconfig kube-scheduler.kubeconfig root@server:"${HOME_DIR}/worker_certificate_$CURRENT_HOSTNAME"
            data_encryption
        fi
    fi
    echo "[KUBECONFIG] Kubeconfig setup completed."
    popd &>/dev/null
}

data_encryption() {
    echo "[DATA-ENCRYPTION] Setting up data encryption for Kubernetes..."
    pushd "${HOME_DIR}" &>/dev/null
    echo "[DATA-ENCRYPTION] Displaying encryption-config.yaml file..."
    cat "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/configs/encryption-config.yaml
    echo "[DATA-ENCRYPTION] Generate an encryption key..."
    export ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)
    envsubst < kubernetes/kubernetes-the-hard-way/configs/encryption-config.yaml > encryption-config.yaml
    scp encryption-config.yaml root@server:"${HOME_DIR}/worker_certificate_$CURRENT_HOSTNAME"
    popd &>/dev/null
    echo "[DATA-ENCRYPTION] Data encryption setup completed."
}

bootstrapping_control_plane () {
    echo "[CONTROL_PLANE] Bootstrapping Control Plane..."
    echo "[ETCD] Let's Bring-up etcd cluster..."
    pushd "${HOME_DIR}"/kubernetes &>/dev/null
    if [[ "server" == "${CURRENT_HOSTNAME}" ]]; then

        if [ -f "${MACHINE_INVENTORY}" ]; then
            while read IP FQDN HOSTNAME SUBNET HOST; do
                echo "RUNNING FOR ${IP} ===> ${HOST} && SUBNET is ${SUBNET}"
                if echo "$HOST" | grep -q "node"; then
                    cp "${HOME_DIR}/kubernetes/kubernetes-the-hard-way/configs/10-bridge.conf" "${HOME_DIR}/worker_certificate_${HOST}/10-bridge.conf"
                    sed "s|SUBNET|$SUBNET|g" "${HOME_DIR}/worker_certificate_${HOST}/10-bridge.conf" > "${HOME_DIR}/worker_certificate_${HOST}/10-bridge.conf"
                    ssh "root@${HOST}" "mkdir -p /etc/cni/net.d"
                    scp "${HOME_DIR}/worker_certificate_${HOST}/10-bridge.conf" root@${HOST}:/etc/cni/net.d/10-bridge.conf
                    scp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/configs/99-loopback.conf root@${HOST}:/etc/cni/net.d/99-loopback.conf
                fi
            done < "${MACHINE_INVENTORY}"
        fi

        echo "[ETCD] Copying etcd and Kubernetes controller binaries to /usr/local/bin..."
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/downloads/controller/etcd /usr/local/bin/
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/downloads/client/etcdctl /usr/local/bin/
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/downloads/controller/kube-apiserver /usr/local/bin/
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/downloads/controller/kube-controller-manager /usr/local/bin/
        ls -l /usr/local/bin/etcd*
        echo "[ETCD] Creating necessary directories for etcd..."
        mkdir -p /etc/etcd /var/lib/etcd /etc/kubernetes/config /var/lib/kubernetes/
        chmod 700 /var/lib/etcd

        echo "[ETCD] Copying etcd certificates to /etc/etcd..."
        pushd "${HOME_DIR}"/kubernetes/CERT &>/dev/null
        echo "[ETCD] Copying etcd certificates to /etc/etcd..."
        cp ca.crt kube-api-server.key kube-api-server.crt /etc/etcd/

        certificates=(
            "ca.crt" "ca.key" "kube-api-server.key" "kube-api-server.crt" "service-accounts.key" 
            "service-accounts.crt" "kube-controller-manager.kubeconfig"
            "kube-scheduler.kubeconfig" "encryption-config.yaml"
        )

        for host in node-0 node-1; do
            pushd "${HOME_DIR}/worker_certificate_${host}"
            for cert in ${certificates[*]}; do
                cp "${cert}" /var/lib/kubernetes/"${host}_${cert}"
            done
            popd &>/dev/null
        done

        chmod 644 /var/lib/kubernetes/*.crt
        chmod 600 /var/lib/kubernetes/*.key

        popd &>/dev/null

        echo "[ETCD] Bringing-up etcd or starting up etcd..."
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/units/etcd.service /etc/systemd/system/
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/units/kube-apiserver.service /etc/systemd/system/kube-apiserver.service
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/units/kube-controller-manager.service /etc/systemd/system/
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/units/kube-scheduler.service /etc/systemd/system/
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/configs/kube-scheduler.yaml /etc/kubernetes/config/
        systemctl daemon-reload
        systemctl enable etcd kube-apiserver kube-controller-manager kube-scheduler
        systemctl start etcd kube-apiserver kube-controller-manager kube-scheduler

        # Wait until kube-apiserver is active
        echo "[WAIT] Waiting for kube-apiserver to become active..."
        while true; do
            status=$(systemctl is-active kube-apiserver)
            echo "[WAIT] Current kube-apiserver status: $status"
            if [[ "$status" == "active" ]]; then
                echo "[CONTROL_PLANE] kube-apiserver is active."
                break
            else
                echo "[WAIT] kube-apiserver status: $status. Retrying in 2 seconds..."
                sleep 2
            fi
        done

        systemctl status kube-apiserver --no-pager

        journalctl -u kube-apiserver | cat

        mkdir -p "${HOME_DIR}"/.kube
        cp "${HOME_DIR}"/kubernetes/CERT/admin.kubeconfig "${HOME_DIR}"/.kube/config
        chown -R ubuntu:ubuntu "${HOME_DIR}"/.kube

        kubectl cluster-info --kubeconfig "${HOME_DIR}"/kubernetes/CERT/admin.kubeconfig

        kubectl apply -f "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/configs/kube-apiserver-to-kubelet.yaml \
            --kubeconfig "${HOME_DIR}"/kubernetes/CERT/admin.kubeconfig

        curl --cacert "${HOME_DIR}"/kubernetes/CERT/ca.crt "${K8S_API_SERVER}:${K8S_API_SERVER_PORT}/version"

        echo "[ETCD] List the etcd cluster members..."
        etcdctl member list
    else
        if echo "$CURRENT_HOSTNAME" | grep -q "node"; then
            echo "[ETCD] Running on nodes host, skipping etcd setup on server nodes..."
        fi
    fi
    popd &>/dev/null
    
}

bootstrapping_worker_node () {
    if echo "$CURRENT_HOSTNAME" | grep -q "node"; then
        apt-get update
        apt-get -y install socat conntrack ipset kmod
        mkdir -p {/etc/cni/net.d,/opt/cni/bin,/var/run/kubernetes, /etc/containerd}
        echo "[WORKER] Copying CNI plugins to /opt/cni/bin..."
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/downloads/cni-plugins/* /opt/cni/bin/
        echo "[WORKER] Copying worker binaries to /usr/local/bin..."
        pushd "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/downloads/worker &>/dev/null
        cp crictl kube-proxy kubelet runc /usr/local/bin/
        cp containerd containerd-shim-runc-v2 containerd-stress /bin/
        popd &>/dev/null
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/downloads/cni-plugins/* /opt/cni/bin/
        modprobe br-netfilter
        echo "br-netfilter" >> /etc/modules-load.d/modules.conf
        lsmod | grep br_netfilter
        echo "net.bridge.bridge-nf-call-iptables = 1" >> /etc/sysctl.d/kubernetes.conf
        echo "net.bridge.bridge-nf-call-ip6tables = 1" >> /etc/sysctl.d/kubernetes.conf
        sysctl -p /etc/sysctl.d/kubernetes.conf
        mkdir -p /etc/containerd/
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/configs/containerd-config.toml /etc/containerd/config.toml
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/units/containerd.service /etc/systemd/system/
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/configs/kubelet-config.yaml /var/lib/kubelet/
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/units/kubelet.service /etc/systemd/system/
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/configs/kube-proxy-config.yaml /var/lib/kube-proxy/
        cp "${HOME_DIR}"/kubernetes/kubernetes-the-hard-way/units/kube-proxy.service /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable containerd kubelet kube-proxy
        systemctl start containerd kubelet kube-proxy
        systemctl is-active containerd kubelet kube-proxy
    fi
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "  -h, --help    Display this help message"
    echo "*#*#*#*#*#*#*#*#*#*#* ${0} setup_base -> to install all dependencies *#*#*#*#*#*#*#*#*#*#*"
    echo "*#*#*#*#*#*#*#*#*#*#* ${0} setup_certificate -> to bring up certificate for all components *#*#*#*#*#*#*#*#*#*#*"
    echo "*#*#*#*#*#*#*#*#*#*#* ${0} setup_kubeconfig -> to configure kubeconfig for all components & data encryption encryption-config.yaml *#*#*#*#*#*#*#*#*#*#*"
    echo "*#*#*#*#*#*#*#*#*#*#* ${0} setup_server -> to bring up the Kubernetes API server *#*#*#*#*#*#*#*#*#*#*"
    # ... other options
}

# =========================
# Main Control Flow
# =========================
INSTALL_TYPE=$1

case "$INSTALL_TYPE" in
    setup_base)
        install_dependencies
        ;;
    setup_certificate)
        certificate_installation
        ;;
    setup_kubeconfig)
        kubeconfig_configuration
        ;;
    setup_control_plane)
        bootstrapping_control_plane
        ;;
    setup_worker_node)
        bootstrapping_worker_node
        ;;
    *)
        usage
        exit 1
        ;;
esac