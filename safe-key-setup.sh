#!/bin/sh

## safe-key-setup

####
#
# Creates a full-strength GPG keypair with configurable sub-key(s) for encryption, signing
# and/or authentication, optionally signs the primary key with specified existing keys,
# optionally imports a specified image, creates a revocation cert, backs them all up to a
# tarball and imports the public primary key and secret subkeys to the main keyring.
#
####
#
# © Copyright 2013-2017 Rowan Thorpe
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Affero General Public License for more details.
#
#  You should have received a copy of the GNU Affero  General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
####
#
# Reference links:
#
#  http://blog.sanctum.geek.nz/linux-crypto-gnupg-keys/
#  http://security.stackexchange.com/questions/31594/what-is-a-good-general-purpose-gnupg-key-setup
#  http://security.stackexchange.com/questions/29851/how-many-gpg-keys-should-i-make
#  http://keyring.debian.org/creating-key.html
#  https://wiki.debian.org/subkeys
#  http://www.openpgp-schulungen.de/scripte/keygeneration/#download
#  https://we.riseup.net/riseuplabs+paow/openpgp-best-practices
#  https://gist.github.com/anonymous/3d928a0bcbb3ed92c454

## FIXME:
#
# * Creating multiple "other addresses" only sets the last one
#
# * Several functions are fragile in a non-batch "screen-scraping" faked-input kind of way
#   (especially WRT "toggling preselected flags"). Find a better way (it appears that at present
#   some of those things can only be improved in GPG itself though?).
#
# * Work out if there is any way to avoid using hibernatable memory (or disable hibernation during
#   this script..!).
#
## TODO:
#
# * Auto-export SSH key from gpg auth key.
#
# * Add all exported files and keyring to memlockd (is also adding gpg main keyring to memlockd
#   generally useful anyway, perhaps?). Use a separate config-fragment which is left in place (*not*
#   removed on EXIT trap), and in the summary warn the user to remove the config and reload memlockd
#   after the relevant files have been moved (not copied) to another medium, and it has been
#   unmounted.
#
# * Set passphrase as part of set_extra_stuff() rather than at the end, then use:
#   >  _printf '%s\n' "${live_pass}" | \
#   >      eval "${SK_PRESET_PASSPHRASE} --preset \"&\${key_grip}\""
#   before the following commands, and at the end use:
#   >  eval "${SK_PRESET_PASSPHRASE} --forget \"&\${key_grip}\""
#   so that there is no window of opportunity (however small) for someone to access the secret key without the passphrase.
#   In presets() add:
#    SK_PRESET_PASSPHRASE="${SK_PRESET_PASSPHRASE:-/usr/lib/gnupg2/gpg-preset-passphrase}"
#
# * Add cv25519 support as an option, and then when it is more widely used switch to it.
#
# * Configurably follow the procedure for smartcards as described at
#   https://gist.github.com/abeluck/3383449
#
# * Add copyright headers from one or two references in the list above, if relevant (can't remember
#   at the moment).
#
# * Perhaps update trust (configurably) of new key in main keyring at the end.

## NB:
#
# * This is still quite context-specific and gpg-version-specific ("works for me") at the moment. I
#   hope to fix that in due course with your help. I would love this tool to become generally useful
#   and would really appreciate any feedback, bug-reports and patches. Particularly I want this to
#   be paranoically safe - for example I use manual memlockd logic to avoid swappable memory but
#   haven't yet worked out how to avoid/temporarily disable(?) computer hibernation to prevent
#   storing passwords to disk.
#
# * Deliberately using same Full Name field and no Comment fields for all UIDs. When making a strong
#   key there should be no ambiguity about the name, and comments are almost always used wrongly
#   (which confuses things later) and are almost never actually needed (the few who do should edit
#   them manually afterwards).
#
# * Deliberately not automating upload to keyserver at the end - I presently think that is just too
#   risky for an automated script and shouldn't be encouraged. If you think I should change my mind
#   please email me and give me your reasoning...

_debug() { test -z "${SK_DEBUG}" || "$@"; }
case "${eol_repr}" in
    '\r\n')
        _printf() { printf "${@}" | sed -e 's/$/\r/'; }
        ;;
    '\r')
        _printf() { printf "${@}" | tr '\n' '\r'; }
        ;;
    *)
        _printf() { printf "${@}"; }
        ;;
esac
_debugprint() { _debug _printf 'DEBUG: %s\n' "${1}" >&2; }
_die() { _printf 'ERROR: %s\n' "${1}" >&2; exit 1; }
_trap() { exit_commands="${1}${eol}${exit_commands}"; trap "${exit_commands}" INT TERM QUIT EXIT; }

####

static_globals() {
    _debugprint 'static_globals()'
    this_script="$(readlink -e "${0}")"
    this_shell="$(readlink -e '/bin/sh')"
    this_pid="${$}"
    time_now="$(date +%Y%m%d%H%M%S)"
    exit_commands=
    has_existing_gpg=
}

memlock() {
    _debugprint 'memlock()'
    _printf -- '+%s\n%s\n' "${this_shell}" "${this_script}" | \
        sudo tee /etc/memlockd.d/temp-memlock-${this_pid}.cfg >/dev/null
    _trap 'sudo rm -f /etc/memlockd.d/temp-memlock-${this_pid}.cfg'
    if sudo service memlockd status >/dev/null 2>&1; then
        memlock_running=1
        sudo service memlockd restart
        _trap 'sudo service memlockd restart'
    else
        memlock_running=
        sudo service memlockd start
        _trap 'sudo service memlockd stop'
    fi
    sudo service memlockd status >/dev/null 2>&1 || _die 'Couldn'\''t lock myself with memlockd'
}

get_opts() {
    _debugprint 'get_opts()'
    while test ${#} -gt 0; do
        case "${1}" in
            --source)
                cat "${this_script}"
                exit 0
                ;;
            --)
                shift
                break
                ;;
            -*)
                _die 'Unknown commandline flag'
                ;;
            *)
                break
                ;;
        esac
    done
}

presets() {
    _debugprint 'presets()'
    USER="${USER:-$(id -un)}" || _die 'Couldn'\''t find ${USER}'
    GROUP="${GROUP:-$(id -gn)}" || _die 'Couldn'\''t find ${GROUP}'
    HOME="${HOME:-$(cd && pwd)}" || _die 'Couldn'\''t find ${HOME}'
    SK_KEY_LENGTH="${SK_KEY_LENGTH:-4096}"
    SK_INVOKE="${SK_INVOKE:-LC_ALL= LC_MESSAGES=C $(command -v gpg2)}" || _die 'Can'\''t find gpg2 command'
    SK_FLAGS="${SK_FLAGS:-${SK_DEBUG:+--verbose --verbose} --armor --with-colons --pinentry-mode loopback --command-fd 0 --status-fd 2}"
    SK_MAIN_BACKUP="${HOME}/gnupg-backup-${time_now}.tar.gz"
    SK_MAIN_HOMEDIR="${SK_MAIN_HOMEDIR:-${HOME}/.gnupg}"
    SK_MAIN_OPTIONS="${SK_MAIN_OPTIONS:-${SK_MAIN_HOMEDIR}/gpg.conf}"
    SK_MAIN_KEYRING="${SK_MAIN_KEYRING:-${SK_MAIN_HOMEDIR}/pubring.kbx}"
    SK_MAIN_FLAGS_NO_BATCH="${SK_MAIN_FLAGS_NO_BATCH:-${SK_FLAGS} --no-default-keyring --homedir \"\${SK_MAIN_HOMEDIR\}\" --options \"\${SK_MAIN_OPTIONS\}\" --keyring \"\${SK_MAIN_KEYRING\}\"}"
    SK_MAIN_FLAGS="${SK_MAIN_FLAGS:-${SK_MAIN_FLAGS_NO_BATCH} --batch}"
    if test -z "${SK_WORKDIR}"; then
        if test -d /dev/shm && test -r /dev/shm && test -x /dev/shm && test -w /dev/shm; then
            SK_WORKDIR='/dev/shm/safe-key-setup'
        else
            SK_WORKDIR="${HOME}/safe-key-setup"
        fi
    fi
    test -n "${SK_NEW_CONF}" || \
        SK_NEW_CONF='## Adapted from https://gist.github.com/anonymous/3d928a0bcbb3ed92c454
##NOTES##
#Read Linux manuals and the GnuPG Options Index to understand these options and apply judgement to change them as needed.
#Use the latest Linux CLI implementation as the default GPG application. Create backups before experimentation.
#
#Create the default directories and .conf files with --version or --gpgconf-test or --list-config.
#Check for reasons behind errors via --debug-all --debug-level guru.
#Always copy this .conf file and all other related files into the ~/.gnupg folder.
#Check results with --list-packets, --check-sigs, --list-keys, --list-chain, or use --dry-run.
#
#A list of cross-platform and widely-supported algorithms is on the GnuPG website. Only the most widely-supported algorithms are mentioned in this .conf file.
#Compiling GPG with a different or newer libgcrypt may allow access to other different algorithms inside libgcrypt.
#
#Always run this command on the GnuPG directory to ensure proper ownership and permissions: "sudo chmod -R 700 ~/.gnupg && sudo chown -R $USER:$GROUP ~/.gnupg".
#General Warning 1: Avoid metadata leaks.
#General Warning 2: Manually change system-time, use tools that spoof system-time, or use faked-system-time before generating keys.
#General Warning 3: When generating keys, set the Master Key to (C)ERTIFY only, and similarly, give only one flag (E, S, A) to each of the subkeys.

##ENCRYPTION PREFERENCES##
#All initial preferences and features placed inside keys which will also apply to any additional generated subkeys as long as the preferences in this file are given.
#Key recipients see these preferences.
#To keep only the basic features: default-preference-list MDC NO-KS-MODIFY
#To remove all preferences and features from a key: default-preference-list NO-MDC KS-MODIFY
#For a realistic and compatibility-aware statement: default-preference-list AES256 CAMELLIA256 TWOFISH CAMELLIA192 AES192 CAMELLIA128 CAST5 IDEA AES128 3DES BLOWFISH SHA512 SHA384 SHA256 SHA224 RIPEMD160 SHA1 BZIP2 ZLIB ZIP UNCOMPRESSED MDC NO-KS-MODIFY
default-preference-list AES256 CAMELLIA256 TWOFISH CAMELLIA192 AES192 CAMELLIA128 CAST5 IDEA AES128 3DES BLOWFISH SHA512 SHA384 SHA256 SHA224 RIPEMD160 SHA1 BZIP2 ZLIB ZIP UNCOMPRESSED MDC NO-KS-MODIFY
#
#The hash algorithm used in the key-signing/certification of oneself'\''s keys and others'\'' keys.
cert-digest-algo SHA512
#
#Symmetric and asymmetric encryption preferences that get reconciled with recipients'\'' preferences.
personal-cipher-preferences AES256 CAMELLIA256 TWOFISH
personal-digest-preferences SHA512
personal-compress-preferences BZIP2 ZLIB ZIP UNCOMPRESSED
#
#Encryption settings that override recipients'\'' preferences and all other preferences in this file.
#Must change as needed and regularly to increase security.
#cipher-algo CAMELLIA256
#s2k-cipher-algo CAMELLIA256
#digest-algo SHA512
#s2k-digest-algo SHA512
#s2k-mode 3
#s2k-count 100000000
force-mdc

##COMPRESSION PREFERENCES##
#Compression settings that override recipients'\'' preferences and all other preferences in this file.
#Must change as needed and regularly to increase security.
#compress-algo BZIP2
#compress-level 9
#bzip2-compress-level 9

##WEB OF TRUST##
#Key-signing/certification general settings for oneself'\''s keys and others'\'' keys.
#The level of trust to assign other people'\''s keys
trust-model pgp
default-cert-level 0
#ask-cert-level
min-cert-level 1
completes-needed 1
marginals-needed 2
max-cert-depth 5
#Signatures, by default, are set not to expire. This can now be changed for each individual signature. Use 0 as a policy.
ask-cert-expire
ask-sig-expire
#default-sig-expire 0
#default-cert-expire 0

##METADATA REMOVAL##
#Do not place the GnuPG version or any comments in your data.
no-emit-version
no-comments
#
#throw-keyids is similar to the --hidden-recipient option but works on all keyids at once. It blocks GnuPG from emitting the keyid on an encrypted packet.
#This makes it difficult but not impossible for someone to deduct the properties of the public-key being used to encrypt a file. Keep changing the public-key to guarantee high secrecy.
#The throw-keyids option does not work on signatures and GnuPG does not hide the keyid in a standalone signature.
#One can Encrypt and Sign together to hide the signature packet under the encryption packet.
#Use available options to specify the secret-key to decrypt with when receiving encrypted files without a keyid. Otherwise, wait for GnuPG to try all secret-keys.
#throw-keyids
#
#for-your-eyes-only overrides --set-filename and forces recipients to pick an output filename and extension.
#Use --set-filename fakeFilename.ext if needed.
for-your-eyes-only
no-use-embedded-filename
#
#ignore-time-conflict overrides prompts regarding timing that occur due to manual time modifications.
ignore-time-conflict
#Manually give --faked-system-time 20070924T154812 to GnuPG if it allows. Remove the comment hashtag below to set a faked-system-time but keep changing it to evade identification.
#faked-system-time 20070924T154812

##RUNTIME##
no-greeting
expert
#interactive
enable-progress-filter
keyid-format 0xLONG
#fingerprint
#fingerprint
with-fingerprint
with-fingerprint
with-keygrip
#verbose
#verbose
#verbose
#verbose
#verbose
#verbose
#verbose
#verbose
#verbose
#verbose
#
#If gpg-agent is non-functional, change the key daemon to the built-in key daemon in Gnome.
#agent-program gnome-keyring-daemon
#
#Cautiousness settings for when looking at or using keys.
#...show-photos... (generally too disruptive, e.g. paging through every photo on desktop login)
list-options show-policy-urls show-notations show-std-notations show-user-notations show-keyserver-urls show-uid-validity show-unusable-uids show-unusable-subkeys show-keyring show-sig-expire show-sig-subpackets
#Add show-usage to list-options when the option becomes available in GnuPG.
verify-options show-photos show-policy-urls show-notations show-std-notations show-user-notations show-keyserver-urls show-uid-validity show-unusable-uids no-show-primary-uid-only no-pka-lookups no-pka-trust-increase
auto-check-trustdb

# when outputting certificates, view user IDs distinctly from keys:
fixed-list-mode

# include an unambiguous indicator of which key made a signature:
# (see http://thread.gmane.org/gmane.mail.notmuch.general/3721/focus=7234)
sig-notation issuer-fpr@notations.openpgp.fifthhorseman.net=%g

# Because some mailers change lines starting with "From " to ">From "
# it is good to handle such lines in a special way when creating
# cleartext signatures; all other PGP versions do it this way too.
# To enable full OpenPGP compliance you may want to use this option.
#no-escape-from-lines

# If you do not pass a recipient to gpg, it will ask for one.  Using this option you can encrypt to a default key.  Key validation will
# not be done in this case.  The second form uses the default key as default recipient.
#default-recipient some-user-id
default-recipient-self

# Photo viewer commandline
photo-viewer "xzgv %i"

##KEYSERVERS##
#Only use keyservers behind a system with blanket internet traffic Onion Routing because keyservers can reveal communication networks.
#Only use the trusted keyservers designated in the gpg.conf file.
#Change to a completely new Onion Routing circuit before and after any communication with keyservers, like refreshing keys. searching for keys, or retrieving keys.
#
#Keyservers used.
#Trusted keyserver for inside-GnuPG access: hkps://hkps.pool.sks-keyservers.net.
#Trusted keyserver for outside-GnuPG website access: https://sks-keyservers.net.
#Trusted email-verified keyserver for manual key transfer through website: https://keyserver.pgp.com.
#All keyserver certificates, including websites'\'' public-key certificates, should be placed under the ~/.gnupg/Keyservers_Certificates directory and used to verify keyservers'\'' authenticity upon each connection that is made.
#To activate the trusted keyserver, remove the two comment-hastags below.
#keyserver-options ca-cert-file=~/.gnupg/sks-keyservers.netCA.pem
#keyserver hkps://hkps.pool.sks-keyservers.net
#
#Keyserver connection settings that help mitigate leakage threats when a connection to a keyserver is made.
#no-auto-key-locate
auto-key-locate local
#keyserver-options no-try-dns-srv no-auto-key-retrieve no-honor-keyserver-url no-honor-pka-record include-revoked include-disabled include-subkeys check-cert
#keyserver-options verbose verbose verbose verbose verbose verbose verbose verbose verbose verbose
#keyserver-options timeout 10
keyserver-options no-auto-key-retrieve no-honor-keyserver-url no-honor-pka-record include-revoked include-subkeys
#
#To manually use a keyserver with an Onion Routing SOCKS5 Proxy on Port 9050, remove the comment-hastag below. Change the port number if needed.
#Warning: Blanket Onion Routing of the whole OS is better. This setting overrides the "http_proxy" environment variable, if any.
#keyserver-options http-proxy=socks5h://127.0.0.1:9050

# When verifying a signature made from a subkey, ensure that the cross
# certification "back signature" on the subkey is present and valid.
# This protects against a subtle attack against subkeys that can sign.
# Defaults to --no-require-cross-certification.  However for new
# installations it should be enabled.
require-cross-certification
'
    test -n "${SK_NEW_AGENT_CONF}" || \
        SK_NEW_AGENT_CONF="\
daemon
#quiet
#disable-scdaemon
allow-loopback-pinentry
#allow-emacs-pinentry
allow-mark-trusted
default-cache-ttl 86400
max-cache-ttl 86400
enable-ssh-support
#default-cache-ttl-ssh 86400
#max-cache-ttl-ssh 86400
#debug-level expert
#pinentry-program $(which pinentry-curses)
#no-grab
#keep-display
#display :0.0
"
}

sanity() {
    _debugprint 'sanity()'
    err_msg=
    test 'xprintf' = "x$(PATH= command -v printf)" || \
        err_msg="${err_msg}+ printf seems to only be provided by an external command which means that
when trying to communicate the password around other users will be able to
snoop it via tools like \"ps\".${eol}"
    if _printf 'Y' | read -n 1 temp >/dev/null 2>/dev/null; then
        read_n1_flag="-n 1"
    else
        read_n1_flag=""
    fi
    { stty -echo && stty echo; } >/dev/null 2>&1 || \
        err_msg="${err_msg}+ stty doesn't seem to work as needed (to not display
password). If you continue be *sure* no-one is watching over your shoulder,
and even then it is still not advised!${eol}"
    if test -s "${SK_MAIN_OPTIONS}"; then
        has_existing_gpg=1
        if ! test "x$(grep -v '^ *\(#\|default-key \|$\)' "${SK_MAIN_OPTIONS}" | sort)" = "x$(_printf '%s\n' "${SK_NEW_CONF}" | grep -v '^ *\(#\|default-key \|$\)' | sort)"; then
            err_msg="${err_msg}+ There is a difference between the uncommented content of ${SK_MAIN_OPTIONS} and that of the bundled conf.${eol}"
        fi
    else
        err_msg="${err_msg}+ You have no existing gpg.conf at ${SK_MAIN_OPTIONS}.${eol}"
    fi
    if test -n "${err_msg}"; then
        cat >&2 <<EOM
${err_msg}

If you know what you are doing and wish to continue anyway, please enter "y".
Anything else aborts.
EOM
        read ${read_n1_flag} reply
        test 'y' = "${reply}" || test 'Y' = "${reply}" || _die 'Bailing out on request'
    fi
}

get_info() {
    _debugprint 'get_info()'
    full_name=
    primary_email_address=
    expire_date=
    image_file=
    stored_pass=
    live_pass=
    while test -z "${full_name}"; do
        _printf 'Enter your full name:\n' >&2
        read full_name
    done
    while test -z "${primary_email_address}"; do
        _printf 'Enter the email address which will be the primary uid:\n' >&2
        read primary_email_address
    done
    _printf 'Enter a space-separated list of the extra email addresses you wish to create uids for (optional):\n' >&2
    read other_email_addresses
    while test -z "${expire_date}"; do
        _printf 'Enter an expiry date in ISO format YYYY-MM-DD (at most five years from now is advised):\n' >&2
        read expire_date
    done
    while ! test -s "${image_file}"; do
        _printf 'Enter filename for a small image file to include in the key\n(optional, file must exist and be non-empty):\n' >&2
        read image_file
        test -n "${image_file}" || break
        image_file="$(readlink -n -e "${image_file}")" || _die 'Image file doesn'\''t exist'
    done
    if test -n "${has_existing_gpg}"; then
        _printf 'Enter existing key(s) which you would like to trust-sign the new key with (optional):\n' >&2
        count=0
        while _printf '  %d: Key ID? (leave empty to finish loop):\n' "${count}" >&2 && \
                  read old_key_${count}_id && \
                  eval "test -n \"\${old_key_${count}_id}\""
        do
            _printf '  %d: Key passphrase? (optional):\n' "${count}" >&2
            stty -echo >/dev/null 2>&1; read old_key_${count}_pass; stty echo >/dev/null 2>&1
            count=$(expr ${count} + 1)
        done
        old_key_total=${count}
        unset old_key_${count}_id
        unset count
    fi
    _printf 'Do you want an encryption subkey? (Y|y=y, anything else=no):\n' >&2
    read include_encrypt_key
    test 'y' = "${include_encrypt_key}" || test 'Y' = "${include_encrypt_key}" || include_encrypt_key=
    _printf 'Do you want a signing subkey? (Y|y=y, anything else=no):\n' >&2
    read include_sign_key
    test 'y' = "${include_sign_key}" || test 'Y' = "${include_sign_key}" || include_sign_key=
    _printf 'Do you want an authentication subkey? (Y|y=yes, anything else=no):\n' >&2
    read include_auth_key
    test 'y' = "${include_auth_key}" || test 'Y' = "${include_auth_key}" || include_auth_key=
    pass_check="##################"
    while :; do
        _printf 'Enter the passphrase for offline-stored key (not echoed):\n' >&2
        stty -echo >/dev/null 2>&1; read stored_pass; stty echo >/dev/null 2>&1
        _printf 'Re-enter the passphrase for the offline-stored key (not echoed):\n' >&2
        stty -echo >/dev/null 2>&1; read pass_check; stty echo >/dev/null 2>&1
        ! test "x${stored_pass}" = "x${pass_check}" || break
        _printf 'Passphrase mismatch, try again.\n' >&2
    done
    pass_check="##################"
    while :; do
        _printf 'Enter the passphrase for the live key (not echoed):\n' >&2
        stty -echo >/dev/null 2>&1; read live_pass; stty echo >/dev/null 2>&1
        _printf 'Re-enter the passphrase for the live key (not echoed):\n' >&2
        stty -echo >/dev/null 2>&1; read pass_check; stty echo >/dev/null 2>&1
        ! test "x${live_pass}" = "x${pass_check}" || break
        _printf 'Passphrase mismatch, try again.\n' >&2
    done
}

prepare_main_dir() {
    _debugprint 'prepare_main_dir()'
    test -d "${SK_WORKDIR}" || mkdir "${SK_WORKDIR}" || _die 'Couldn'\''t create workdir "%s"' "${SK_WORKDIR}"
    if ! mkdir "${SK_MAIN_HOMEDIR}" 2>/dev/null; then
        sudo chown -R "${USER}:${GROUP}" "${SK_MAIN_HOMEDIR}"
        chmod -R 700 "${SK_MAIN_HOMEDIR}"
        tar --warning=no-file-ignored --transform "s:^${HOME}:.:" -c -z \
            -f "${SK_MAIN_BACKUP}" "${SK_MAIN_HOMEDIR}" || \
            _die 'Failed to backup existing gnupg directory'
        chmod 400 "${SK_MAIN_BACKUP}"
    fi
}

create_temp_dir() {
    _debugprint 'create_temp_dir()'
    SK_NEW_BASEDIR="${SK_NEW_BASEDIR:-$(mktemp --tmpdir="${SK_WORKDIR}" --directory "${time_now}-XXX")}" || _die 'Couldn'\''t create base directory with mktemp'
    SK_NEW_HOMEDIR="${SK_NEW_HOMEDIR:-${SK_NEW_BASEDIR}/dot_gnupg}"
    SK_NEW_AGENT_OPTIONS="${SK_NEW_AGENT_OPTIONS:-${SK_NEW_HOMEDIR}/gpg-agent.conf}"
    SK_NEW_OPTIONS="${SK_NEW_OPTIONS:-${SK_NEW_HOMEDIR}/gpg.conf}"
    SK_NEW_KEYRING="${SK_NEW_KEYRING:-${SK_NEW_HOMEDIR}/pubring.kbx}"
    SK_NEW_FLAGS_NO_BATCH="${SK_NEW_FLAGS_NO_BATCH:-${SK_FLAGS} --no-default-keyring --homedir \"\${SK_NEW_HOMEDIR\}\" --options \"\${SK_NEW_OPTIONS\}\" --keyring \"\${SK_NEW_KEYRING\}\"}"
    SK_NEW_FLAGS="${SK_NEW_FLAGS:-${SK_NEW_FLAGS_NO_BATCH} --batch}"
    mkdir "${SK_NEW_HOMEDIR}" || _die 'Couldn'\''t mkdir new gnupg directory'
    _printf '%s\n' "${SK_NEW_AGENT_CONF}" >"${SK_NEW_AGENT_OPTIONS}"
    _printf '%s\n' "${SK_NEW_CONF}" >"${SK_NEW_OPTIONS}"
}

generate_key() {
    _debugprint 'generate_key()'
    _printf '%%echo Starting generation of key.
Key-Type: RSA
Key-Length: %s
Key-Usage: cert
Name-Real: %s
Name-Email: %s
Expire-Date: %s
%%no-protection
%%commit
%%echo Finished generating key.
' "${SK_KEY_LENGTH}" "${full_name}" "${primary_email_address}" "${expire_date}" | \
        eval "${SK_INVOKE} ${SK_NEW_FLAGS} --gen-key >&2"
}

get_primary_key_grip() {
    _debugprint 'get_primary_key_grip()'
    key_grip="$(
        eval "${SK_INVOKE} ${SK_NEW_FLAGS} --list-secret-keys" | \
            sed -n \
                -e '/^grp:/! b' \
                -e 's/^grp:\\+\\([^:]\\+\\):\\+\$/\\1/' \
                -e 's/ //g' \
                -e 'p' \
                -e 'q'
    )"
    _printf '
default-key &%s
' "${key_grip}" >>"${SK_NEW_OPTIONS}"
}

set_extra_stuff() {
    _debugprint 'set_extra_stuff()'
    for addr in ${other_email_addresses}; do # full-name, email, comment
        input_text="${input_text}adduid${eol}${full_name}${eol}${addr}${eol}${eol}"
    done
    subkeys_count=0
    if test -n "${incl_encr_key}"; then # key-type, toggle-flags-the-q, key-length, key-expiry, password
        input_text="${input_text}addkey${eol}8${eol}s${eol}q${eol}${SK_KEY_LENGTH}${eol}1y${eol}${eol}"
        subkeys_count=$(expr ${subkeys_count} + 1)
    fi
    if test -n "${incl_sign_key}"; then # key-type, toggle-flags-the-q, key-length, key-expiry, password
        input_text="${input_text}addkey${eol}8${eol}e${eol}q${eol}${SK_KEY_LENGTH}${eol}1y${eol}${eol}"
        subkeys_count=$(expr ${subkeys_count} + 1)
    fi
    if test -n "${incl_auth_key}"; then # key-type, toggle-flags-the-q, key-length, key-expiry, password
        input_text="${input_text}addkey${eol}8${eol}e${eol}s${eol}a${eol}q${eol}${SK_KEY_LENGTH}${eol}1y${eol}${eol}"
        subkeys_count=$(expr ${subkeys_count} + 1)
    fi
    if test -n "${image_file}"; then # file
        input_text="${input_text}addphoto${eol}${image_file}${eol}"
    fi
    input_text="${input_text}save${eol}"
    _printf '%s' "${input_text}" | \
        eval "${SK_INVOKE} ${SK_NEW_FLAGS} --edit-key \"&\${key_grip}\""
}

gen_revoke() {
    _debugprint 'gen_revoke()'
    master_revoke_cert="${SK_NEW_BASEDIR}/master-revoke-cert.asc"
    _printf 'y\n0\nRevocation cert created at key-creation time\n\ny\n' | \
        eval "${SK_INVOKE} ${SK_NEW_FLAGS_NO_BATCH} --output \"\${master_revoke_cert}\" --gen-revoke \"&\${key_grip}\""
}

pivot() {
    _debugprint 'pivot()'
    eval "${SK_INVOKE} ${SK_NEW_FLAGS} --export \"&\${key_grip}\" | ${SK_INVOKE} ${SK_MAIN_FLAGS} --import"
    for count in $(seq 0 $(expr ${old_key_total} - 1 || :)); do
        eval "_printf 'tnrsign\\ny\\ny\\n2\\n10\\n\\ny\\n%s\\nsave\\n' \"\${old_key_${count}_pass}\" | ${SK_INVOKE} ${SK_MAIN_FLAGS} --local-user \"\${old_key_${count}_id}\" --edit-key \"&\${key_grip}\""
    done
    eval "${SK_INVOKE} ${SK_MAIN_FLAGS} --export \"&\${key_grip}\" | ${SK_INVOKE} ${SK_NEW_FLAGS} --import --import-options merge-only"
    eval "${SK_INVOKE} ${SK_NEW_FLAGS} --export-secret-subkeys \"&\${key_grip}\" | ${SK_INVOKE} ${SK_MAIN_FLAGS} --import --import-options merge-only"
}

export_owner_trust() {
    _debugprint 'export_owner_trust()'
    owner_trust="${SK_NEW_BASEDIR}/owner-trust.txt"
    eval "${SK_INVOKE} ${SK_NEW_FLAGS} --export-ownertrust" >"${owner_trust}"
}

set_passphrases() {
    {
        _printf 'passwd%s\n'
        for x in $(seq $(expr ${subkeys_count} + 1)); do
            _printf '%s\n' "${live_pass}"
        done
    } | \
        eval "${SK_INVOKE} ${SK_MAIN_FLAGS} --edit-key \"&\${key_grip}\""
    {
        _printf 'passwd%s\n'
        for x in $(seq $(expr ${subkeys_count} + 1)); do
            _printf '%s\n' "${stored_pass}"
        done
    } | \
        eval "${SK_INVOKE} ${SK_NEW_FLAGS} --edit-key \"&\${key_grip}\""
}

summary() {
    _debugprint 'summary()'
    _printf "\
Your public primary key and secret subkeys are installed in your keyring, and for storage the \
full master key & subkeys are in a separate keyring at \"%s\", the owner-trust is exported at \
\"%s\", and a master revocation certificate is stored at \"%s\". Unless you manually overrode \
their locations they are on a tmpfs (to avoid later retrieval by disk-imaging), so be sure to \
move them to safe long-term storage immediately to avoid losing them, and be sure not to \
forget the \"stored\" passphrase in addition to your "live" passphrase. Once you are convinced \
everything is in working order send key to the keyserver with:
 gpg --keyserver pool.sks-keyservers.net --send-key '%s'\n\n" \
            "${SK_NEW_HOMEDIR}" "${owner_trust}" "${master_revoke_cert}" "&${key_grip}" >&2
}

####

main() {
    _debugprint 'main()'
    static_globals
    memlock
    get_opts
    presets
    sanity
    get_info
    prepare_main_dir
    create_temp_dir
    generate_key
    get_primary_key_grip
    set_extra_stuff
    gen_revoke
    pivot
    export_owner_trust
    set_passphrases
    summary
}

####

set -e
_debug set -x

umask 077
eol='
'
eol_repr="$(printf '%s' "${eol}" | od -A n -t c | sed -e 's/ //g')"

! test 'safe-key-setup.sh' = "$(_printf '%s\n' "${0}" | sed -e 's:^.*/::')" || main
