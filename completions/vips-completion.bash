#/usr/bin/env bash

# bash completions for the "vips" command

# copy to /etc/bash_completion.d to install

_vips_compgen_f()
{
  COMPREPLY=($(compgen -f -- "${COMP_WORDS[-1]}"))

  if [ ${#COMPREPLY[@]} = 1 ]; then
    local LASTCHAR=
    if [ -d "$COMPREPLY" ]; then
      LASTCHAR=/
    fi

    COMPREPLY=$(printf %q%s "$COMPREPLY" "$LASTCHAR")
  else
    for ((i=0; i < ${#COMPREPLY[@]}; i++)); do
      if [ -d "${COMPREPLY[$i]}" ]; then
        COMPREPLY[$i]=${COMPREPLY[$i]}/
      fi
    done
  fi
}

_vips_completions()
{
  if [ ${#COMP_WORDS[@]} == "2" ]; then
    COMPREPLY=($(compgen -W "$(vips -c)" "${COMP_WORDS[1]}"))
  else
    local args=($(vips -c ${COMP_WORDS[1]}))
    local arg_type=${args[${#COMP_WORDS[@]}-3]}
    if [ x$arg_type == x"" ]; then
      COMPREPLY=
    elif [ $arg_type == "file" ]; then
      _vips_compgen_f
    elif [[ $arg_type = word:* ]]; then
      local options=$(echo $arg_type | sed 's/word://' | sed 's/|/ /g')
      COMPREPLY=($(compgen -W "${options[@]}" "${COMP_WORDS[-1]}"))
    fi
  fi
}

complete -F _vips_completions vips
