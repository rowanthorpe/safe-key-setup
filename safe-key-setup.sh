#!/bin/sh

## safe-key-setup

####
# Creates a full-strength GPG keypair with a sub-key for encryption, optional multiple sub-keys
# for signing, optionally signs the key with specified existing keys, optionally imports a
# specified image, creates a revocation cert, backs up the master secret key and removes it from
# the main keyring (so it can be kept separate from the public master and subkeys, for use only
# when necessary).
####
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
####
# Reference links (TODO: may need to copy some license-headers from one or two of these if they
#                  have actual code similar to mine...?):
#
#  http://blog.sanctum.geek.nz/linux-crypto-gnupg-keys/
#  http://security.stackexchange.com/questions/31594/what-is-a-good-general-purpose-gnupg-key-setup
#  http://security.stackexchange.com/questions/29851/how-many-gpg-keys-should-i-make
#  http://keyring.debian.org/creating-key.html
#  https://wiki.debian.org/subkeys
#  http://www.openpgp-schulungen.de/scripte/keygeneration/#download
#  https://we.riseup.net/riseuplabs+paow/openpgp-best-practices


# NB:
#
# * I only had time to throw this together enough to "work for me". I know there are things that
#   still need ironing out, but my free-time is a bit sporadic at the moment. However I would love
#   this tool to become generally useful and would really appreciate any feedback, bug-reports and
#   patches. Particularly I want this to be paranoically safe - I have already used a weird hack
#   with a foregrounded memlockd to avoid swappable memory but haven't yet worked out how to
#   (temporarily disable?) avoid computer hibernation storing passwords to disk. Thanks.
#
# * Deliberately using same Full Name field and no Comment fields for all UIDs. When making a strong master
#   key there should be no ambiguity about the name, and comments are almost always used wrongly (which
#   confuses things later) and are almost never actually needed (the few who do should edit them manually).
#
# * Deliberately not offering to upload it to a keyserver at the end - I presently think that is
#   just too risky in an automated script and shouldn't be encouraged. If you think I should change
#   my mind please email me and give me your reasoning...

# FIXME:
#
#       [straight-forward stuff]
#
# * Make all code tolerate filenames with embedded space (this will introduce lots of evals
#   though...).
#
# * Set the password from the moment the key is created (so there is no window of vulnerability)
#   and pipe the password in for all steps using $HIDDEN_PRINTF. "gpgwrap" manpage has some
#   examples that might be a good resource (not needing to actually use gpgwrap though).
#
# * Redirect this script's STDIN to /dev/null during keys' creation so any entropy assistance
#   (typing) won't be inserted later as gibberish when trying to save the key.
#
# * Use and respect gpg lock files (e.g. secring.gpg.lock, etc), for obvious reasons.
#
# * Manually audit this script and confirm each gpg invocation is inputting exactly the expected
#   sequence of text.
#
#       [not so simple stuff]
#
# * Work out if there is any way to avoid using hibernatable memory (or disable hibernation
#   during this script).
#
#       [can only be improved in gpg, not here -> heads-up gpg devs...!]
#
# * At present GPG's batch generation capability is not mature, so this script necessarily reverts
#   to hackish, not-future-proof, fragile "faked input" in some places. The only proper solution
#   to this is to improve GPG though.
#
# * It is only possible to specify one subkey during automated key creation, so the extra subkeys,
#   etc have to be added via an extra step. The "proper way" is for the GPG developers to extend its
#   batch generation facility for [A] multiple subkeys during key generation, and [B] adding subkeys
#   to existing keys, etc.

# TODO:
#
#       [when I have time]
#
# * Add copyright headers from one or two references in the list above, if relevant (can't remember
#   at the moment).
#
# * Add "set -e" to the top of the script and check that every command is failproofed.
#
#       [to decide if wise first]
#
# * Perhaps automate updating trustdb (configurably), after all other actions are done.

die() {
    printf 'ERROR: ' >&2
    printf "$@" >&2
    exit 1
}

# Getopts
thisscript="$(readlink -e "$0")"
while test $# -gt 0; do
	case "$1" in
	--source)
		cat "$thisscript"
		exit 0
                ;;
	--)
		shift
		break
                ;;
	-*)
		die 'Unknown commandline flag.%s' "$eol"
                ;;
	*)
		break
                ;;
	esac
done

## This is a perverse hack to lock the whole script into non-swappable memory
printf -- '%s%s' "$thisscript" "$eol" >/dev/shm/temp-memlock-$$.cfg
sudo /usr/sbin/memlockd -c /dev/shm/temp-memlock-$$.cfg -u memlockd -f -d >/dev/null 2>&1 &
mlockpid=$!
sleep 1
ps $mlockpid >/dev/null || die 'Couldn'\''t lock myself with memlockd.%s' "$eol"

## Don't create anything readable by other users (except root...)
umask 077

## Presets. Overridable by env vars...
GPGINVOKE="${GPGINVOKE:-LC_ALL= LC_MESSAGES=C $(command -v gpg2)}" || die 'Can'\''t find gpg2 command.%s' "$eol"
HOME="${HOME:-$(cd && pwd)}" || die 'Couldn'\''t find $HOME.%s' "$eol"
HIDDEN_PRINTF="${HIDDEN_PRINTF:-$(PATH= command -v printf)}" # output is sanity-tested below
GNUPGHOME="${GNUPGHOME:-${HOME}/.gnupg}"
GNUPGCONF="${GNUPGCONF:-${GNUPGHOME}/gpg.conf}"
GNUPGPUBKEYRING="${GNUPGPUBKEYRING:-${GNUPGHOME}/pubring.gpg}"
GNUPGSECKEYRING="${GNUPGSECKEYRING:-${GNUPGHOME}/secring.gpg}"
if test -z "$SAFEKEY_WORKDIR"; then
	if test -d /dev/shm && test -r /dev/shm && test -x /dev/shm && test -w /dev/shm; then
		SAFEKEY_WORKDIR=/dev/shm
	else
		SAFEKEY_WORKDIR="$HOME"
	fi
fi
SAFEKEY_KEYRING_SETTINGS="${SAFEKEY_KEYRING_SETTINGS:---options $GNUPGCONF --armor --expert --batch --command-fd 0}"
SAFEKEY_MAINKEYRING_SETTINGS="${SAFEKEY_MAINKEYRING_SETTINGS:-$SAFEKEY_KEYRING_SETTINGS --homedir $GNUPGHOME}"
eol="
"
## End of presets

timenow="$(date +%Y%m%d%H%M%S)"

## Backup existing gpg directory if it exists
mkdir "${HOME}/.gnupg/" 2>/dev/null || \
	tar -czf "${HOME}/gnupg-backup-${timenow}.tar.gz" -C "$HOME" .gnupg

## Check some settings are sane, secure and functional first...
errmsg=
if test -z "$HIDDEN_PRINTF"; then
	errmsg="${errmsg}+ The printf seems to only be provided by an external command which means that
when trying to communicate the password around other users will be able to
snoop it via tools like \"ps\".$eol"
elif test "printf" = "$HIDDEN_PRINTF"; then
	HIDDEN_PRINTF="PATH= printf"
fi
if printf 'Y' | read -n 1 temp >/dev/null 2>/dev/null; then
	read_n1_flag="-n 1"
else
	read_n1_flag=""
fi
{ stty -echo && stty echo; } >/dev/null 2>&1|| \
	errmsg="${errmsg}+ stty doesn't seem to work as needed (to not display
password). If you continue be *sure* no-one is watching over your shoulder,
and even then it is still not advised!$eol"
grep -q '^personal-digest-preferences[ '"$(printf '\t')"']\+SHA512[ '"$(printf '\t')"']*$' "$GNUPGCONF" || \
	errmsg="${errmsg}+ Your personal-digest-preferences appear not to contain SHA512.$eol"
grep -q '^cert-digest-algo[ '"$(printf '\t')"']\+SHA512[ '"$(printf '\t')"']*$' "$GNUPGCONF" || \
	errmsg="${errmsg}+ Your cert-digest-algo does not appear to be SHA512.$eol"
gpgconf_def_pref="\
$(sed -n \
	-e '/^default-preference-list[ \t]/! b' \
	-e ':loop' \
	-e '/\\$/! n last' \
	-e 'N' \
	-e 's/\\\r\?\n//' \
	-e 'b loop' \
	-e ': last' \
	-e 'p' \
	-e 'q' \
"$GNUPGCONF")"
for x in SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed; do
	printf "$gpgconf_def_pref" | grep -q '^default-preference-list[ '"$(printf '\t')"'].*\<'"$x"'\>' || \
		errmsg="${errmsg}+ Your default-preference-list appears not to contain \"${x}\".$eol"
done
if test -n "$errmsg"; then
	cat >&2 <<EOM
$errmsg

If you know what you are doing and wish to continue anyway, please enter "y".
Anything else aborts.
EOM
	read $read_n1_flag reply; test "y" = "$reply" || test "Y" = "$reply" || die 'Bailing out on request.%s' "$eol"
fi

## Get user info
fullname=
primaryemailaddress=
expiredate=
pass=
while test -z "$fullname"; do
	printf 'Enter your full name:%s' "$eol" >&2
	read fullname
done
while test -z "$primaryemailaddress"; do
	printf 'Enter the email address which will be the primary uid:%s' "$eol" >&2
	read primaryemailaddress
done
while test -z "$expiredate"; do
	printf 'Enter an expiry date in ISO format YYYY-MM-DD (at most five years from now is advised):%s' "$eol" >&2
	read expiredate
done
imagefile=
while ! test -s "$imagefile"; do
	printf 'Enter filename for a small image file to include in the key%s(optional, file must exist '\
'and be non-empty):%s' "$eol" "$eol" >&2
	read imagefile
	test -n "$imagefile" || break
	imagefile="$(readlink -n -e "$imagefile")" || die 'Image file doesn'\''t exist.%s' "$eof"
done
printf 'Enter a space-separated list of the extra email addresses you wish to create uids for (optional):%s' "$eol" >&2
read otheremailaddresses
printf 'Enter space-separated key IDs which you would like to sign the new key with (optional):%s' "$eol" >&2
read oldkeys
printf 'Enter how many signing subkeys you want created (optional):%s' "$eol" >&2
read numsignkeys
test -n "$numsignkeys" || numsignkeys=0
pass=
passcheck="##################"
while ! test "$pass" = "$passcheck"; do
	while test -z "$pass"; do
		printf 'Enter a passphrase (not echoed):%s' "$eol" >&2
		stty -echo >/dev/null 2>&1; read pass; stty echo >/dev/null 2>&1
	done
	printf 'Please re-enter the passphrase (not echoed):%s' "$eol" >&2
	stty -echo >/dev/null 2>&1; read passcheck; stty echo >/dev/null 2>&1
done
subpass=
passcheck="##################"
while ! test "$subpass" = "$passcheck"; do
	while test -z "$subpass"; do
		printf 'Enter a passphrase for the subkeys (not echoed):%s' "$eol" >&2
		stty -echo >/dev/null 2>&1; read subpass; stty echo >/dev/null 2>&1
	done
	printf 'Please re-enter the passphrase for the subkeys (not echoed):%s' "$eol" >&2
	stty -echo >/dev/null 2>&1; read passcheck; stty echo >/dev/null 2>&1
done

## Create temp stuff
tempgpgdir="$(mktemp --tmpdir="$SAFEKEY_WORKDIR" --directory)" || die 'Couldn'\''t create temporary directory.%s' "$eol"
trap 'test -z "$tempgpgdir" || rm -Rf "$tempgpgdir" 2>/dev/null' EXIT
SAFEKEY_TEMPKEYRING_SETTINGS="${SAFEKEY_TEMPKEYRING_SETTINGS:-$SAFEKEY_KEYRING_SETTINGS --homedir $tempgpgdir \
	--no-default-keyring --keyring ${tempgpgdir}/pubring.gpg --secret-keyring ${tempgpgdir}/secring.gpg}"

## Generate key
eval "cat <<EOM | $GPGINVOKE $SAFEKEY_TEMPKEYRING_SETTINGS --gen-key >&2
%echo Starting generation of key.
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign auth
Subkey-Type: RSA
Subkey-Length: 4096
Subkey-Usage: encrypt
Name-Real: \$fullname
Name-Email: \$primaryemailaddress
Expire-Date: \$expiredate
Passphrase: \$subpass
%pubring \${tempgpgdir}/pubring.gpg
%secring \${tempgpgdir}/secring.gpg
%commit
%echo Finished generating key.
EOM
"

## Get master key ID
eval "keyid=\"\$($GPGINVOKE $SAFEKEY_TEMPKEYRING_SETTINGS --list-keys --with-colons | \
	sed -n \
		-e '/^pub:/! b' \
		-e 's/^pub:[^:]*:[^:]*:[^:]*:\([^:]\+\):.*$/\1/' \
		-e 'p'
)\""

## Generate extra UIDs, signing subkeys, import image, etc
{
	printf 'keyid 1%sprimary%s' "$eol" "$eol"
	for addr in $otheremailaddresses; do
		printf 'adduid%s%s%s%s%s%s' "$eol" "$fullname" "$eol" "$addr" "$eol" "$eol" "$eol"
	done
	for num in $(seq $numsignkeys); do
		printf 'addkey%s8%se%sq%s4096%s1y%s' "$eol" "$eol" "$eol" "$eol" "$eol" "$eol"
	done
	if test -n "$imagefile"; then
		printf 'addphoto%s%s%s' "$eol" "$imagefile" "$eol"
	fi
	printf 'setpref SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed%s' "$eol"
	printf 'save%s' "$eol"
} | eval "$GPGINVOKE $SAFEKEY_TEMPKEYRING_SETTINGS --edit-key \$keyid"

master_revoke="${SAFEKEY_WORKDIR}/master-key-revoke-${timenow}.asc"
master_secret="${SAFEKEY_WORKDIR}/master-secret-key-${timenow}.asc"
master_public="${SAFEKEY_WORKDIR}/master-public-key-${timenow}.asc"
sub_secret="${SAFEKEY_WORKDIR}/secret-subkeys-${timenow}.asc"
keys_tarball="${HOME}/gpg-keys-${timenow}.tar.gz"

#TODO: do this when all ok
## If any keys were specified for signing the new key with...
#if test -n "$oldkeys"; then
#	# Pipe-export master public key | import to main keyring (don't save as file)
#	eval "$GPGINVOKE $SAFEKEY_TEMPKEYRING_SETTINGS --export \$keyid | $GPGINVOKE $SAFEKEY_MAINKEYRING_SETTINGS --import"
#	# Sign it on main keyring, with requested IDs
#	for signame in $oldkeys; do
#		printf 'tnrsign%s2%s10%s%ssave%s' "$eol" "$eol" "$eol" "$eol" "$eol" | \
#			eval "$GPGINVOKE $SAFEKEY_MAINKEYRING_SETTINGS --local-user \"\$signame\" --edit-key \$keyid"
#	done
#	# Pipe-export master public key | import to temp keyring (don't save as file)
#	eval "$GPGINVOKE $SAFEKEY_MAINKEYRING_SETTINGS --export \$keyid | $GPGINVOKE $SAFEKEY_TEMPKEYRING_SETTINGS --import"
#	# Delete master public key from main keyring
#	eval "$GPGINVOKE $SAFEKEY_MAINKEYRING_SETTINGS --delete-key \$keyid"
#fi

## Set password
eval "$HIDDEN_PRINTF 'passwd%s%s%ssave%s' \"\$eol\" \"\$pass\" \"\$eol\" \"\$eol\" | \
	$GPGINVOKE $SAFEKEY_TEMPKEYRING_SETTINGS --edit-key \$keyid"
## Export revocation cert to file
eval "$GPGINVOKE $SAFEKEY_TEMPKEYRING_SETTINGS --output \"\$master_revoke\" --gen-revoke \$keyid"
## Export master secret key to file
eval "$GPGINVOKE $SAFEKEY_TEMPKEYRING_SETTINGS --output \"\$master_secret\" --export-secret-key \$keyid"
## Export master public key to file
eval "$GPGINVOKE $SAFEKEY_TEMPKEYRING_SETTINGS --output \"\$master_public\" --export \$keyid"
## Export secret subkeys to file
eval "$GPGINVOKE $SAFEKEY_TEMPKEYRING_SETTINGS --output \"\$sub_secret\" --export-secret-subkeys"

#TODO: when all is good do this too...
## Import master public and secret subkeys to main keyring
#eval "$GPGINVOKE $SAFEKEY_MAINKEYRING_SETTINGS --import \"\$master_public\" \"\$sub_secret\""

## Archive the new keys
tar -czf "$keys_tarball" "$master_secret" "$master_public" "$sub_secret" "$master_revoke"

printf "\
Your master public key and secret subkeys are installed in your keyring, and the secret & public master \
keys, secret sub-keys, and revocation certificate are saved as \"%s\", \"%s\", \"%s\", and \"%s\". Store \
them somewhere safe, and *don't lose them or the passphrase*. Once you are sure it looks in working order \
send it to the keyserver with:
gpg --keyserver pool.sks-keyservers.net --send-key '%s'%s" \
	"$master_secret" "$master_public" "$sub_secret" "$master_revoke" "$keyid" "$eol$eol" >&2

sudo kill $mlockpid
## When this exits the tempdir/keyring will be auto-deleted by the trapped EXIT command
