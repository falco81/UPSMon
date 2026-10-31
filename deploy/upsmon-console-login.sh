# The upsmon console when root signs in (upsmon 4.0, as otp has it).
# Switched with `upsmon --console-at-login on|off`; q in the console leaves it
# for this shell, and `upsmon --console` opens it again. Nothing happens for a
# command run over SSH, scp/sftp, a non-interactive shell, a shell opened
# from the console itself, or when UPSMON_NO_CONSOLE is set.
if [ -n "${PS1:-}" ] && [ -t 0 ] && [ -t 1 ] && [ -z "${UPSMON_CONSOLE:-}" ] \
   && [ -z "${UPSMON_NO_CONSOLE:-}" ] && [ -z "${SSH_ORIGINAL_COMMAND:-}" ] \
   && [ "$(id -u 2>/dev/null)" = "0" ] && [ -x /usr/local/bin/upsmon ] \
   && [ -f /etc/upsmon-console-login ] && [ ! -L /etc/upsmon-console-login ] \
   && [ "$(head -c 3 /etc/upsmon-console-login 2>/dev/null)" = "on" ]; then
    export UPSMON_CONSOLE=1
    /usr/local/bin/upsmon --console
fi
