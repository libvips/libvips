#/usr/bin/env bash

# bash completions for the "vips" command

# copy to /etc/bash_completion.d to install

_vips_completions()
{
  if [ "${#COMP_WORDS[@]}" == "2" ]; then
    COMPREPLY=($(compgen -W "$(vips -c)" "${COMP_WORDS[1]}"))
  fi
}

complete -F _vips_completions vips
