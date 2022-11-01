#/usr/bin/env bash

# bash completions for the "vips" command

# copy to /etc/bash_completion.d to install

_vips_completions()
{
  if [ ${#COMP_WORDS[@]} == "2" ]; then
    COMPREPLY=($(compgen -W "$(vips -c)" "${COMP_WORDS[1]}"))
  else
    local args=($(vips -c ${COMP_WORDS[1]}))
    local arg_type=${args[${#COMP_WORDS[@]}-3]}
    local suggestions
    if [ $arg_type == "file" ]; then
      suggestions=($(compgen -f "${COMP_WORDS[-1]}"))
    elif [[ $arg_type = word:* ]]; then
      local options=$(echo $arg_type | sed 's/word://' | sed 's/|/ /g')
      suggestions=($(compgen -W "${options[@]}" "${COMP_WORDS[-1]}"))
    fi
    COMPREPLY=(${suggestions[@]})
  fi
}

complete -F _vips_completions vips
