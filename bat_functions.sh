#!/usr/bin/env bash

# AWS, Kubectx, Vault & p10k helper functions
# 

# Version: 1.0.18

# Changes
# 1.0.18 - Minor fixes, tidy-ups and stuff from shellcheck
# 1.0.17 - Roll back profile override forcing as its confusing
# 1.0.16 - Add aws 'keys' command to set/clear keys
# 1.0.15 - Add aws 'test/creds' function to see if creds work - calls 'aws sts get-caller-identity'
# 1.0.14 - Add colour to cpu_temp, green under 60, red over 75
# 1.0.13 - Add p10k prompt stuff, requires adding to your PROMPT variable in ~/.p10k.zsh (aws_keys,vault,cpu_temp)
# 1.0.12 - Clear the kubectl context properly
# 1.0.11 - Detect wether to use config or credentials for AWS (credentials takes precedence - no mixing!)
# 1.0.10 - Added vault helper to get token ( and clear variable after 1 hour )
# 1.0.9 - Switch to using ~/.aws/credentials - NOT ~/.aws/config for vault compatability - no '[profile XXX] expected in credentials file'
#         See - https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_credentials_profiles.html
# 1.0.8 - Switch platform to icons in ec2 - nerdfonts required probably
# 1.0.7 - Fix the kube stuff
# 1.0.6 - Add kubectx
# 1.0.5 - remove ssh/rdp param from pf cmd; work out automatically
# 1.0.4 - Tidy how fzf is called
# 1.0.3 - Bug fixes & simplifications
#

# Dependencies: fzf, zsh, aws cli, kubectl, vault, kubectx & osx-cpu-temp
#
# Notes:
# This causes the vault token to be persisted into ~/.bat/vault_token
# and read out on shell start, so it's a global variable
# It will be cleared after 1 hour
# AWS vars are not persisted; yet..
#


##############################################
## init

mkdir -p ~/.bat
# Clear any tokens older than 1 hour
find ~/.bat -name vault_token -type f -mmin +60 -delete
# If it's still there grab the variable
if [[ -f ~/.bat/vault_token ]]; then
  local token
  token=$(< ~/.bat/vault_token)
  export VAULT_TOKEN=${token}
else
  unset VAULT_TOKEN
fi


################################################
## aws
# 
# Usage: 
# aws - Select profile from list
# aws [PROFILE] - set profile if found in ~/.aws/config (none or clear will clear the profile)
# aws keys - echo currently set aws keys
# aws keys set - Ask for both access and secret key - make sure to use single quotes around secret key!
# aws keys set [access_key] - set AWS_ACCESS_KEY_ID variable to [access_key] and request AWS_ACCESS_SECRET_KEY
# aws keys set [access_key] [secret key] - set AWS_ACCESS_KEY_ID to [access_key] and AWS_ACCESS_SECRET_KEYto [secret_key]
# aws keys clear - wipe any keys
# aws pf [instance name/instance id/asg name] [local port - default 9999] - port-forward to selected instance
# aws ec2 - get all ec2 hosts in account
# aws ec2 [COMMAND] - passthrough to normal aws cli
# aws cf [COMMAND] - cloudformation shortcut
# aws [COMMAND] - passthrough to normal aws cli

aws() {
  # Profiles
  if [[ -z "$1" ]]; then
    local profile
    profile=$( _aws_profiles | fzf --header='Select AWS Profile' <<< 'none')
    if [[ -z "${profile}" ]]; then 
      echo "Not changing AWS profile."
      return
    fi
    if [[ "${profile}" = "none" ]];then
      unset AWS_DEFAULT_PROFILE AWS_PROFILE AWS_EB_PROFILE
      echo "AWS profile cleared."
      return
    elif [[ $(_aws_profiles) =~ ${profile} ]]; then
      export AWS_PROFILE=${profile}
      echo "AWS_PROFILE set to ${profile}."
      return
    else
      echo "Error: Profile not found ${profile}."
      exit 1
    fi
  fi
  if [[  "$1" = "none" || "$1" = "clear" ]]; then
      unset AWS_DEFAULT_PROFILE AWS_PROFILE AWS_EB_PROFILE
      echo "AWS profile cleared."
      return
  fi
  if [[ $(_aws_profiles) =~ $1 ]]; then
    export AWS_PROFILE=$1
    return
  

  # Port Forwarding
  elif [[ "$1" = "pf" ]]; then
    local instance_id
    local local_port
    local remote_port

    if [[ -z "$2" ]]; then
      ec2_array=()
      while IFS='' read -r line; do ec2_array+=("$line"); done < <(_ec2)
      instance_id=${ec2_array[2]}
    elif [[ "$2" =~ ^i-[0-9a-z]+ ]]; then
      instance_id=$2;
    else
      # Here we try to get just an instanceId for the name in case it is singular
      instance_id=$(aws ec2 describe-instances \
                     --filter "Name=tag:Name,Values=$2" \
                     --query "Reservations[].Instances[?State.Name == 'running'].InstanceId[]" \
                     --output text)
      IFS=$'\t' read -r -A array <<< "${instance_id}"
      if [[ "${#array[@]}" -gt 1 ]];then
        instance_id=$(_ec2 "$2" | awk '{print $2;}') 
      fi
    fi

    if [[ -z "$3" ]]; then
      local_port=9999
    else
      local_port=$4
    fi
    if [[ -z ${instance_id} ]]; then
      instance_id=$(_ec2 | awk '{print $2;}')
    fi
    if [[ "${instance_id}" =~ ^i-[0-9a-z]+ ]]; then
      if [[ "$(_get_platform "${instance_id}")" =~ "windows" ]]; then
        remote_port=3389
        echo "Opening RDP Port(3389) on ${instance_id}. Local port ${local_port}. Ctrl-C to close."
      else
        remote_port=22
        echo "Opening SSH Port(22) on ${instance_id}. Local port ${local_port}. Ctrl-C to close."
      fi
      aws ssm start-session --target "${instance_id}" \
                       --document-name AWS-StartPortForwardingSession \
                       --parameters '{"portNumber":["'"${remote_port}"'"],"localPortNumber":["'"${local_port}"'"]}'
      return
    else 
      echo "No EC2 Instance Ids found for port forwarding on ${instance_id}"
      return
    fi

  ## test
  elif [[ "$1" = "test" || "$1" = "creds" ]]; then
    aws sts get-caller-identity
    return

  ## keys
  elif [[ "$1" = "keys" ]]; then
    if [[ -z "$2" ]]; then
      echo "Access key: ${AWS_ACCESS_KEY_ID}"
      echo "Secret key: ${AWS_SECRET_ACCESS_KEY}"
      return
    fi
    if [[ "$2" = "clear" ]]; then
      unset AWS_ACCESS_KEY_ID
      unset AWS_SECRET_ACCESS_KEY
      echo "AWS keys cleared"
      return
    fi
    if [[ "$2" = "set" ]]; then
      if [[ -n "$3" ]]; then
         export AWS_ACCESS_KEY_ID=$3
         if [[ -z "$4" ]]; then
           echo "AWS Access key set, please enter secret key and hit return.."
           read -r -s AWS_SECRET_ACCESS_KEY
         else
           export AWS_SECRET_ACCESS_KEY=$4
         fi
       else
         echo "Please enter ACCESS key and hit return"
         read -r -s AWS_ACCESS_KEY_ID
         echo "AWS Access key set, please enter secret key and hit return.."
         read -r -s AWS_SECRET_ACCESS_KEY
      fi
      echo "Access key: $AWS_ACCESS_KEY_ID"
      echo "Secret key: $AWS_SECRET_ACCESS_KEY"
    fi

  ## ec2
  elif [[ "$1" = "ec2" ]]; then
    if [[ -z "$2" ]]; then
      _ec2
      return
    else
      /usr/local/bin/aws "$@"
      return
    fi
 
  ## shortcuts
  elif [[ "$1" = "cf" || "$1" = "cfn" ]];then
    shift
    /usr/local/bin/aws cloudformation "$@"
    return

  ## passthru
  else
    /usr/local/bin/aws "$@"
    return
  fi
}

_aws_profiles() {
  if [[ -f ~/.aws/credentials ]]; then
    sed -n -e 's#\[\(.*\)\]#\1#p' ~/.aws/credentials
  elif [[ -f ~/.aws/config ]]; then
    sed -n -e 's#\[profile \(.*\)\]#\1#p' ~/.aws/config
  else
    echo "Error: Neither ~/.aws/config nor ~/.aws/credentials found"
    exit 1
  fi
}

_aws_get_profile() {
  echo "${AWS_PROFILE}"
}

_ec2() {
    # should match list of tags above
    echo -e "$(<<-EOF tr -d '\n' | sed -e 's#\ \{2,\}##g'
        Name tag,
        Instance ID,
        W/L,
        Public DNS,
EOF
    )\n$(_ec2_hosts "$1")" \
        | column -t -s ',' \
            | fzf --header-lines 1
}

_ec2_hosts() {
   local filters='Name=instance-state-name,Values=running'
   if [[ -n "$1" ]]; then
     filters='{"Name":"instance-state-name","Values":"running","Name":"tag:Name","Values":["'$1'"]}'
   fi
   /usr/local/bin/aws ec2 \
      describe-instances \
          --filters "${filters}" \
          --query "$(<<-EOF tr -d '\n' | tr -d ' '
                Reservations[*].{
                  deets:Instances[*].[
                     (not_null(Tags[?Key==\`Name\`][].Value)[0]||\`_\`),
                     InstanceId,
                     (not_null(Platform)||\`\`),
                     (not_null(PublicDnsName)||\`_\`)
                  ][]
               }
EOF
)" \
          --output json \
        | jq -r '.[]|[.account] + .deets|join(",")'  | sort -u | sed -e 's/windows//g'
}

_get_platform() {
   /usr/local/bin/aws ec2 \
      describe-instances \
         --instance-ids "$1" \
         --query "Reservations[].Instances[?State.Name == 'running'].Platform[]"
}

####################################################################
## kubectl

# Usage:
# kubectl - Select context from list
# kubectl [CONTEXT] - set context if found in ~/.kube/config
# kubectl pf - shortcut for kubectl port-forward

kubectl() {
  if [[ -z "$1" ]]; then
    _set_kubectl_context "$( _get_kubectl_contexts | fzf --header='Select kubectl context'<<< 'none')"
  elif [[ "$1" = "none" ]]; then
    _set_kubectl_context none
    return
  elif [[ $(_get_kubectl_contexts) =~ $1 ]]; then
    /usr/local/bin/kubectx "$1"
    return
  elif [[ "$1" = "pf" ]]; then
    shift
    /usr/local/bin/kubectl port-forward "$@"
    return
  else
    /usr/local/bin/kubectl "$@"
    return
  fi
}

_set_kubectl_context() {
  if [[ -z "$1" ]]; then
    echo "Not changing Kubernetes context"
    return
  fi
  if [[ "$1" = "none" ]]; then
    echo "Clearing kubectl context"
    /usr/local/bin/kubectl config unset current-context
    echo "Clearing P9K_KUBECONTEXT_CLUSTER P9K_KUBECONTEXT_NAME and P9K_KUBECONTEXT_NAMESPACE"
    unset P9K_KUBECONTEXT_CLUSTER P9K_KUBECONTEXT_NAME P9K_KUBECONTEXT_NAMESPACE
    return
  elif [[ $(_get_kubectl_contexts) =~ $1 ]]; then
    /usr/local/bin/kubectx "$1"
    return
  else
    echo "Error: Unrecognised Kubernetes context $1"
    exit 1
  fi
}


_get_kubectl_contexts() {
  < ~/.kube/config grep -A4 '\- context:' | grep 'name:' | sed -e  's/name: //g' | sed -e 's/ //g'
}

########################################
## Vault

# Usage:
# vault [token] - Get vault token from the configured repo - will set VAULT_TOKEN and persist to ~/.bat/vault_token
# vault [COMMAND] - passthru vault command
#
# NOTE: set VAULT_ADDR to something else if you want to override it

vault() {
  if [[ -v VAULT_ADDR ]]; then
    export VAULT_ADDR='https://vault.tools.thefork.tech'
  fi
  if [[ "$1" = "token" ]]; then
    if ! [[ -v VAULT_TOKEN ]]; then
      _vault_get_token
    elif [[ "$2" == "--force" ]]; then
      echo "Forcing new token"
      _vault_get_token
    else
      echo "VAULT_TOKEN already set; to force new one add --force"
    fi
    echo "Vault token: ${VAULT_TOKEN}"
    return
  else
    /usr/local/bin/vault "$@"
  fi
}

_vault_get_token() {
  if [[ -f ~/.bat/vault_token ]]; then
    rm ~/.bat/vault_token
  fi
  local token
  token="$(unset AWS_ACCESS_KEY_ID&&unset AWS_SECRET_ACCESS_KEY&&AWS_PROFILE=thefork&&vault login -method=aws -token-only role=trf-iamrole_vault-config-auth-iam-core)"
  export VAULT_TOKEN=${token}
  if [[ -n "${token}" ]]; then
    echo "${token}" >> ~/.bat/vault_token
  fi
}

########################################
## p10k prompt helper functions
#
# To use add any of aws_keys, cpu_temp, vault to your left or right prompts in ~/.p10k.zsh
#

## vault_token is written to a file when set so we can tell it's age
# Sets prompt if vault token is set
function prompt_vault() {
  find ~/.bat -name vault_token -type f -mmin +60 -delete
  if [[ -f ~/.bat/vault_token ]]; then
    local token
    token=$(< ~/.bat/vault_token)
    export VAULT_TOKEN=${token}
  else
    unset VAULT_TOKEN
  fi
  if [[ -v VAULT_TOKEN ]]; then
    p10k segment -f 021 -r -i LOCK_ICON -t "${VAULT_TOKEN:0:6}.."
  fi
}

# Adds a CPU temp readout - requires 'brew install osx-cpu-temp' 
function prompt_cpu_temp() {
  cpu_temp=$(/usr/local/bin/osx-cpu-temp)
  # Orange
  colour=208
  # Green
  if [[ 60 -gt "${cpu_temp:0:2}" ]]; then 
    colour=113
  fi
  # Red
  if [[ 75 -lt "${cpu_temp:0:2}" ]]; then
    colour=197
  fi

  p10k segment -f "${colour}" -i ' ' -t "${cpu_temp}"
}

function prompt_aws_keys() {
  if [[ -n "${AWS_ACCESS_KEY_ID}" ]]; then
      p10k segment -f 208 -r -i AWS_ICON -t " ..${AWS_ACCESS_KEY_ID:(-6)}"
  fi
}

# Below simply call the functions above for the instant prompt
function instant_prompt_vault() {
  prompt_vault
}

function instant_prompt_cpu_temp() {
  prompt_cpu_temp
}

function instant_prompt_aws_keys() {
  prompt_aws_keys
}
