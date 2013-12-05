#!/bin/sh

## safe-key-setup

####
# Creates a full-strength GPG keypair with a sub-key for encryption, optional multiple sub-keys
# for signing, optionally signs the key with specified existing keys, optionally imports a
# specified image, creates a revocation cert, backs up the master secret key and removes it from
# the main keyring (so it can be kept separate from the public master and subkeys, for use only
# when necessary).
####

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
#   key there should be no ambiguity about the name, and comments are almost alway used wrongly (which
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
#   and pipe the password in for all steps using $HIDDEN_PRINTF.
#
# * Redirect this script's STDIN to /dev/null so any entropy assistance (typing) during keys'
#   creation won't be inserted later as gibberish when trying to save the key.
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
#       [to decide if wise first]
#
# * Perhaps automate updating trustdb (configurably), after all other actions are done.

# Reference links:
#
# http://blog.sanctum.geek.nz/linux-crypto-gnupg-keys/
# http://security.stackexchange.com/questions/31594/what-is-a-good-general-purpose-gnupg-key-setup
# http://security.stackexchange.com/questions/29851/how-many-gpg-keys-should-i-make
# http://keyring.debian.org/creating-key.html
# https://wiki.debian.org/subkeys
# http://www.openpgp-schulungen.de/scripte/keygeneration/#download
# https://we.riseup.net/riseuplabs+paow/openpgp-best-practices



# The next four lines are a perverse hack to lock this whole script into non-swappable memory
thisscript="$(readlink -e "$0")"
printf -- '%s\n' "$thisscript" >/dev/shm/temp-memlock-$$.cfg
sudo /usr/sbin/memlockd -c /dev/shm/temp-memlock-$$.cfg -u memlockd -f -d >/dev/null 2>&1 &
mlockpid=$!
# don't create anything readable by other users (except root, of course)
umask 077

## Preset these here. They can be overriden by env vars...
if test -z "$GPGINVOKE"; then
	if command -v gpg2 >/dev/null 2>&1; then
		GPGINVOKE='LC_ALL= LC_MESSAGES=C gpg2'
	else
		GPGINVOKE='LC_ALL= LC_MESSAGES=C gpg'
	fi
fi
HOME="${HOME:-$(cd && pwd)}"
GNUPGHOME="${GNUPGHOME:-${HOME}/.gnupg}"
GNUPGCONF="${GNUPGCONF:-${GNUPGHOME}/gpg.conf}"
GNUPGPUBKEYRING="${GNUPGPUBKEYRING:-${GNUPGHOME}/pubring.gpg}"
GNUPGSECKEYRING="${GNUPGSECKEYRING:-${GNUPGHOME}/secring.gpg}"
if test -z "$SAFEKEY_WORKDIR"; then
	if test -d /dev/shm && -r /dev/shm && -x /dev/shm && -w /dev/shm; then
		SAFEKEY_WORKDIR=/dev/shm
	else
		SAFEKEY_WORKDIR="$HOME"
	fi
fi
SAFEKEY_KEYRINGSETTINGS="${SAFEKEY_KEYRINGSETTINGS:---options $GNUPGCONF --armor --expert --batch --command-fd 0}"
SAFEKEY_MAINKEYRINGSETTINGS="${SAFEKEY_MAINKEYRINGSETTINGS:-$SAFEKEY_KEYRINGSETTINGS --homedir $GNUPGHOME}"
HIDDEN_PRINTF="${HIDDEN_PRINTF:-$(PATH= command -v printf)}" 2>/dev/null
eol="
"
## End of presets

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
if ! printf 'Hmmm...\n' | read -s temp >/dev/null 2>/dev/null; then
	errmsg="${errmsg}+ Your shell's \"read\" doesn't seem to cope with -s flag (to not display
password). If you continue be *sure* no-one is watching over your shoulder,
and even then it is still not advised!$eol"
fi
if ! grep -q '^personal-digest-preferences[ \t].*\<SHA512\>' "$GNUPGCONF"; then
	errmsg="${errmsg}+ Your personal-digest-preferences appear not to contain SHA512.$eol"
fi
if ! grep -q '^cert-digest-algo[ \t].*\<SHA512\>' "$GNUPGCONF"; then
	errmsg="${errmsg}+ Your cert-digest-algo does not appear to be SHA512.$eol"
fi
gpgconf_def_pref="\
$(sed -ne '/^default-preference-list[ \t]/ { :loop; /\\$/ { N; s/\\\n//; b loop }; p }' "$GNUPGCONF")"
for x in SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed; do
	if ! printf "$gpgconf_def_pref" | grep -q "^default-preference-list[ \t].*\<${x}\>"; then
		errmsg="${errmsg}+ Your default-preference-list appears not to contain \"${x}\".$eol"
	fi
done
if test -n "$errmsg"; then
	cat >&2 <<EOM
$errmsg

If you know what you are doing and wish to continue anyway, please enter "y".
Anything else aborts.
EOM
	read $read_n1_flag reply; test "y" = "$reply" || test "Y" = "$reply" || exit 1
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
imagefile="##################"
while test -n "$imagefile" && ! test -s "$imagefile"; do
	printf 'Enter (absolute path) filename for a small image file to include in the key%s(optional, file must exist and be non-empty):%s' "$eol" "$eol" >&2
	read imagefile
done
printf 'Enter a space-separated list of the extra email addresses you wish to create uids for (optional):%s' "$eol" >&2
read otheremailaddresses
printf 'Enter space-separated key IDs which you would like to sign the new key with (optional):%s' "$eol" >&2
read oldkeys
printf 'Enter how many signing subkeys you want created (optional):%s' "$eol" >&2
read numsignkeys
if test -z "$numsignkeys"; then
	numsignkeys=0
fi
pass=
passcheck="##################"
while ! test "$pass" = "$passcheck"; do
	while test -z "$pass"; do
		printf 'Enter a passphrase (not echoed):%s' "$eol" >&2
		read -s pass
	done
	printf 'Please re-enter the passphrase (not echoed):%s' "$eol" >&2
	read -s passcheck
done

## Create temp stuff
tempgpgdir="$(mktemp --tmpdir="$SAFEKEY_WORKDIR" --directory)" || {
	printf "Couldn't create temporary directory.%s" "$eol" >&2
	exit 1
}
trap 'rm -Rf "$tempgpgdir" 2>/dev/null' EXIT
SAFEKEY_TEMPKEYRINGSETTINGS="${SAFEKEY_TEMPKEYRINGSETTINGS:-$SAFEKEY_KEYRINGSETTINGS --homedir $tempgpgdir \
--no-default-keyring --keyring ${tempgpgdir}/pubring.gpg --secret-keyring ${tempgpgdir}/secring.gpg}"

## Generate key
cat <<EOM | $GPGINVOKE $SAFEKEY_TEMPKEYRINGSETTINGS --gen-key >&2
%echo Starting generation of key.
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign auth
Subkey-Type: RSA
Subkey-Length: 4096
Subkey-Usage: encrypt
Name-Real: $fullname
Name-Email: $primaryemailaddress
Expire-Date: $expiredate
%pubring ${tempgpgdir}/pubring.gpg
%secring ${tempgpgdir}/secring.gpg
%no-protection
%commit
%echo Finished generating key.
EOM

## Get master key ID
keyid="$($GPGINVOKE $SAFEKEY_TEMPKEYRINGSETTINGS --list-keys --with-colons | \
sed -ne '/^pub:/ { s/^pub:[^:]*:[^:]*:[^:]*:\([^:]\+\):.*$/\1/; p }')"

## Generate extra UIDs, signing subkeys, import image, etc
{
	printf 'keyid 1%sprimary%s' "$eol" "$eol"
	for addr in $otheremailaddresses; do
		printf 'adduid%s%s%s%s%s%s' "$eol" "$fullname" "$eol" "$addr" "$eol" "$eol" "$eol"
	done
	for num in `seq $numsignkeys`; do
		printf 'addkey%s8%se%sq%s4096%s1y%s' "$eol" "$eol" "$eol" "$eol" "$eol" "$eol"
	done
	if test -n "$imagefile"
		printf 'addphoto%s%s%s' "$eol" "$imagefile" "$eol"
	fi
	printf 'setpref SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed%s' "$eol"
	printf 'save%s' "$eol"
} | $GPGINVOKE $SAFEKEY_TEMPKEYRINGSETTINGS --edit-key $keyid

timenow=`date +%Y%m%d%H%M%S`
master_revoke="${HOME}/master-key-revoke-${timenow}.asc"
master_secret="${HOME}/master-secret-key-${timenow}.asc"
master_public="${SAFEKEY_WORKDIR}/master-public-key-${timenow}.asc"
sub_secret="${SAFEKEY_WORKDIR}/secret-subkeys-${timenow}.asc"

## If any keys were specified for signing the new key with...
if test -n "$oldkeys"; then
	# Pipe-export master public key | import to main keyring (don't save as file)
	$GPGINVOKE $SAFEKEY_TEMPKEYRINGSETTINGS --export $keyid | $GPGINVOKE $SAFEKEY_MAINKEYRIGNSETTINGS --import
	# Sign it on main keyring, with requested IDs
	for signame in $oldkeys; do
		printf 'tnrsign%s2%s10%s%ssave%s' "$eol" "$eol" "$eol" "$eol" "$eol" | $GPGINVOKE $SAFEKEY_MAINKEYRINGSETTINGS --local-user "$signame" --edit-key $keyid
	done
	# Pipe-export master public key | import to temp keyring (don't save as file)
	$GPGINVOKE $SAFEKEY_MAINKEYRINGSETTINGS --export $keyid | $GPGINVOKE $SAFEKEY_TEMPKEYRIGNSETTINGS --import
	# Delete master public key from main keyring
	$GPGINVOKE $SAFEKEY_MAINKEYRINGSETTINGS --delete-key $keyid
fi
## Set password
$HIDDEN_PRINTF 'passwd%s%s%ssave%s' "$eol" "$pass" "$eol" "$eol" | $GPGINVOKE $SAFEKEY_TEMPKEYRINGSETTINGS --edit-key $keyid
## Export revocation cert to file
$GPGINVOKE $SAFEKEY_TEMPKEYRINGSETTINGS --output "$master_revoke" --gen-revoke $keyid
## Export key
$GPGINVOKE $SAFEKEY_TEMPKEYRINGSETTINGS --output "$master_secret" --export-secret-key $keyid
## Export master public key to file
$GPGINVOKE $SAFEKEY_TEMPKEYRINGSETTINGS --output "$master_public" --export $keyid
## Export subkeys
$GPGINVOKE $SAFEKEY_TEMPKEYRINGSETTINGS --output "$sub_secret" --export-secret-subkeys
## Reimport master public and secret subkeys to main keyring
$GPGINVOKE $SAFEKEY_MAINKEYRINGSETTINGS --import "$master_public" "$sub_secret"
rm -f "$master_public" "$sub_secret"

printf "Your master public key and secret subkeys are installed in your keyring, and the master secret key and \
revocation certificate are saved as \"%s\" and \"%s\". Store them somewhere safe, and *don't lose them, or the \
passphrase*.%s" "$master_secret" "$master_revoke" "$eol$eol" >&2

sudo kill $mlockpid
## When this exits the tempdir/keyring will be auto-deleted by the trapped EXIT command
