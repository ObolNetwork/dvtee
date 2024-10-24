#!/bin/bash

IP_ADDR="23.83.71.60"
GUEST_SSH_KEY_PATH="./snp-guest-key"
GUEST_USER="amd"
HOST_SSH_PORT="10022"

# Web3Signer configuration files
W3S_CONFIG_DIR="configuration"
W3S_CONFIG_FILE="config.yaml"
W3S_CERT_DIR="${W3S_CONFIG_DIR}/tls"

###############################################################################
# Functions
usage() {
  >&2 echo "Usage: $0 [OPTIONS] [COMMAND]"
  >&2 echo "    run-dkg   CHARON_DIR_PATH   Run a DKG"
  >&2 echo "                                (requires a .charon directory path argument)"
  >&2 echo "    start-w3s CLIENT_FILE_PATH  Start the Web3Signer server"
  >&2 echo "                                (requires a file path argument that contains known trusetd"
  >&2 echo "                                clients for TLS communications)"
  >&2 echo "    stop-w3s                    Stop the Web3Signer server"
  >&2 echo "  where OPTIONS are:"
  >&2 echo "    -h|--help                   Usage information"

  return 1
}

ssh_guest_command() {
  [ -n "${1}" ] || { >&2 echo -e "No guest command specified"; return 1; }

  # Remove fail on error
  set +eE; set +o pipefail

  # Run the SSH command and stream output
  ssh -p ${HOST_SSH_PORT} \
    -i ${GUEST_SSH_KEY_PATH} \
    -o "StrictHostKeyChecking no" \
    -o "PasswordAuthentication=no" \
    -o ConnectTimeout=1 \
    ${GUEST_USER}@${IP_ADDR} "${1}"
  
  local return_code=$?

  # Reset fail on error
  set -eE; set -o pipefail

  # Return with the exit code from SSH
  return ${return_code}
}

scp_guest_command() {
  [ -n "${1}" ] || { >&2 echo -e "No scp source specified"; return 1; }
  [ -n "${2}" ] || { >&2 echo -e "No scp target specified"; return 1; }

  scp -r -P ${HOST_SSH_PORT} \
    -i ${GUEST_SSH_KEY_PATH} \
    -o "StrictHostKeyChecking no" \
    -o "PasswordAuthentication=no" \
    -o ConnectTimeout=1 \
    "${1}" "${2}"
}

prepare_dkg() {
  # Create .charon directory
  ssh_guest_command "mkdir -p .charon"

  # Copy the ENR private key into .charon directory
  scp_guest_command "${1}/charon-enr-private-key" "${GUEST_USER}@${IP_ADDR}:~/.charon"

  # Copy the cluster definition file into .charon directory
  scp_guest_command "${1}/cluster-definition.json" "${GUEST_USER}@${IP_ADDR}:~/.charon"
}

run_dkg() {
  ssh_guest_command "sudo docker run --rm -v \"/home/${GUEST_USER}/:/opt/charon\" obolnetwork/charon:v1.1.1 dkg --publish"

  # Create a key config yaml file for each keystore
  ssh_guest_command 'cd ~/.charon/validator_keys && \
    for file in keystore-*.json; \
    do i=$(echo $file | grep -o "[0-9]\+"); \
    echo -e "type: \"file-keystore\"\nkeyType: \"BLS\"\nkeystoreFile: \"keystore-$i.json\"\nkeystorePasswordFile: \"keystore-$i.txt\"" > keystore-$i.yaml; \
    done'

  # Make keystore passwords readable for web3signer
  ssh_guest_command 'cd ~/.charon/validator_keys && \
    for file in keystore-*.txt; \
    do chmod 444 $file; \
    done'
}

build_w3s_config_file() {
  # Use a yaml configuration file for starting Web3Signer
  ssh_guest_command "mkdir -p \"${W3S_CONFIG_DIR}\" && \
    touch \"${W3S_CONFIG_DIR}/${W3S_CONFIG_FILE}\""

  ssh_guest_command "cat <<EOF > \"${W3S_CONFIG_DIR}/${W3S_CONFIG_FILE}\"
http-listen-port: 9000
http-host-allowlist: \"*\"
key-store-path: /opt/keystore
tls-keystore-file: /opt/certs/mykeystore.p12
tls-keystore-password-file: /opt/certs/password.txt
tls-known-clients-file: /opt/certs/knownClients.txt
eth2.slashing-protection-enabled: false
EOF"
}

build_w3s_server_cert() {
  # Generate a self-signed server TLS certificate for secure Web3Signer communications
  ssh_guest_command "mkdir -p \"${W3S_CERT_DIR}\" && \
    cd \"${W3S_CERT_DIR}\" && \
    openssl ecparam -name prime256v1 -genkey -noout -out privatekey.pem && \
    openssl req -new -x509 -key privatekey.pem -out certificate.pem -days 365 -subj \"/O=DV Labs/CN=${IP_ADDR}\" && \
    openssl rand -base64 16 > password.txt && \
    openssl pkcs12 -export -out mykeystore.p12 -inkey privatekey.pem -in certificate.pem -passout pass:\$(cat password.txt) && \
    chmod 444 mykeystore.p12"
}

run_w3s_server() {
  # Run Web3Signer using the configuration file
  ssh_guest_command "sudo docker run -d \
    --restart unless-stopped \
    --name web3signer \
    -v ~/.charon/validator_keys:/opt/keystore \
    -v ~/${W3S_CONFIG_DIR}:/opt/config \
    -v ~/${W3S_CERT_DIR}:/opt/certs \
    -p 9000:9000 \
    consensys/web3signer:develop \
    --config-file=/opt/config/config.yaml \
    eth2"
}

##############################################################################
# Main

main() {
  # A command must be specified
  if [ -z "${1}" ]; then
    usage
    return 1
  fi

  while [ -n "${1}" ]; do
    case "${1}" in
      -h|--help)
        usage
        ;;

      run-dkg)
        COMMAND="run-dkg"
        # Check if a file path argument is provided
        shift
        if [ -n "${1}" ]; then
          CHARON_DIR_PATH="${1}"  # Capture the charon directory path argument
          [[ "${CHARON_DIR_PATH}" != */ ]] && CHARON_DIR_PATH="${CHARON_DIR_PATH}/"
        else
          >&2 echo "Error: run-dkg requires a charon directory path argument."
          usage
          return 1
        fi
        shift
        ;;

      start-w3s)
        COMMAND="start-w3s"
        # Check if a file path argument is provided
        shift
        if [ -n "${1}" ]; then
          CLIENT_FILE_PATH="${1}"  # Capture the file path argument
        else
          >&2 echo "Error: start-w3s requires a known clients file path argument."
          usage
          return 1
        fi
        shift
        ;;

      stop-w3s)
        COMMAND="stop-w3s"
        shift
        ;;

      -*|--*)
        >&2 echo -e "Unsupported Option: [${1}]\n"
        usage
        return 1
        ;;

      *)
        >&2 echo -e "Unsupported Command: [${1}]\n"
        usage
        return 1
        ;;
    esac
  done

  # Execute command
  case "${COMMAND}" in
    help)
      usage
      return 1
      ;;

    run-dkg)
      if [ -z "${CHARON_DIR_PATH}" ]; then
        >&2 echo "Error: No charon directory path provided for run-dkg."
        usage
        return 1
      fi
      # Remove .charon dir because .charon/cluster-definition.json cannot be overwritten
      # ssh_guest_command "rm -rf ~/.charon"
      prepare_dkg ${CHARON_DIR_PATH}
      run_dkg
      ;;

    start-w3s)
      if [ -z "${CLIENT_FILE_PATH}" ]; then
        >&2 echo "Error: No known clients file path provided for start-w3s."
        usage
        return 1
      fi
      # Remove certificates dir because p12 keystores cannot be overwritten
      ssh_guest_command "rm -rf ~/${W3S_CERT_DIR}"
      build_w3s_config_file
      build_w3s_server_cert
      # Transfer the client certificate to the server for mutual TLS
      scp_guest_command "$CLIENT_FILE_PATH" "${GUEST_USER}@${IP_ADDR}:~/${W3S_CERT_DIR}/knownClients.txt"
      # Transfer the server certificate to the client for mutual TLS
      scp_guest_command "${GUEST_USER}@${IP_ADDR}:~/${W3S_CERT_DIR}/certificate.pem" "./server_certificate.pem"
      run_w3s_server
      ;;

    stop-w3s)
      ssh_guest_command "sudo docker stop web3signer"
      ;;

    *)
      >&2 echo -e "Unsupported Command: [${1}]\n"
      usage
      return 1
      ;;
  esac
}

main "${@}"
