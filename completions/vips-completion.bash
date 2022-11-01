#/usr/bin/env bash

# bash completions for the "vips" command

# copy to /etc/bash_completion.d to install

complete -W "$(vips -c)" vips
