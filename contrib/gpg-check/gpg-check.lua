if confget("RPM::GPG::Check/b", "true") == "false" then
    return
end

if table.getn(files_install) < 1 then
    return
end

hash = '##############################'
hashestotal = string.len(hash)
interactive = confget("RPM::Interactive/b", "true")
quiet = tonumber(confget("quiet", 0))
keyspath = confget("RPM::GPG::KeysPath/f", "/etc/pki/rpm-gpg")

function printhash(amount, total)
    percent = amount/total*100
    if interactive == "true" then
        nrhash = hashestotal - hashestotal / total * amount
        line = string.format("%-31s[%3d%%]", string.sub(hash, nrhash), percent)
        io.stdout.write(io.stdout, line)
        io.stdout.flush(io.stdout)
        for i = 1, string.len(line) do
            io.stdout.write(io.stdout, '\b')
        end
    else
        io.stdout.write(io.stdout, string.format("%%%% %f\n", percent))
    end
end
	
function showerrors(i, msg)
    apterror(msg)
end

good = 1
unknown = 0
illegal = 0
unsigned = 0
missing = 0
errors = {}
missings = {}

skiplist = confgetlist("RPM::GPG::Skip-Check", "")

-- Results are stored in global variables
function gpgcheck(silent)
    good = 1
    unknown = 0
    illegal = 0
    unsigned = 0
    missing = 0
    errors = {}
    missings = {}

    if not silent then
        io.stdout.write(io.stdout, string.format("%-41s", _("Checking GPG signatures...")))
        if interactive == "false" then
            io.stdout.write(io.stdout, '\n')
        end
    end

    for i, file in ipairs(files_install) do
        local skipthis = false
        for j, skip in ipairs(skiplist) do
            start = string.find(pkgname(pkgs_install[i]), skip)
            if start then
                skipthis = true
                aptwarning(_("Skipped GPG check on ")..pkgname(pkgs_install[i]))
                break
            end
        end

        if not silent and quiet == 0 then
            printhash(i, table.getn(files_install))
        end

        if skipthis == false then
            local inp = io.popen("LANG=C /bin/rpm --checksig  "..file.." 2>&1")
            for line in inp.lines(inp) do
                if string.find(line, "rpmReadSignature") then
                    table.insert(errors, _("Illegal signature ")..line)
                    illegal = illegal + 1
                    good = nil
                elseif string.find(line, " NOT OK") then
                    local index = string.find(line, "#")
                    if string.find(line, "MISSING") and index then
                        local keyid = string.lower(string.sub(line, index+1, index+8))
                        table.insert(errors, _("Missing key ")..line)
                        if not missings[keyid] then
                            missings[keyid] = {}
                        end
                        table.insert(missings[keyid], file)
                        missing = missing + 1
                        good = nil
                    else
                        table.insert(errors, _("Unknown error ")..line)
                        unknown = unknown + 1
                        good = nil
                    end
                elseif string.find(line, " OK") then
                    if string.find(line, " gpg") or string.find(line, " pgp") then
                        break
                    else
                        table.insert(errors, _("Unsigned ")..line)
                        unsigned = unsigned + 1
                        good = nil
                    end
                else
                    table.insert(errors, _("Unknown error ")..line)
                    unknown = unknown + 1
                    good = nil
                end
            end
            io.close(inp)
        end
    end
    if not silent and interactive == "true" then
        io.stdout.write(io.stdout, '\n')
    end
end

gpgcheck(false)

if not good and confget("RPM::GPG::Import-Missing/b", "true") == "true" then
    -- Print list of missing keys
    for i, msglist in pairs(missings) do
        for j, file in pairs(msglist) do
            print(_("   missing key #")..i.._(" for ")..file)
        end
    end

    -- Search for missing keys
    local keysimported = 0
    local files = posix.dir(keyspath)
    for i, file in ipairs(files) do
        -- Get the Key ID
        local keyid = nil
        local inp = io.popen("LANG=C /usr/bin/gpg --no-options --no-default-keyring --keyring /dev/null --secret-keyring /dev/null "..keyspath.."/"..file.." 2>&1")
        for line in inp.lines(inp) do
    	    if string.sub(line, 1, 4) == "pub " then
                keyid = string.lower(string.sub(line, 12, 19))
            end
        end
        io.close(inp)

        if keyid and missings[keyid] then
            -- Note: Single kay could be imported several times
            -- So neither pkgfind() nor `rpm -e --test` can be used
            local ret = os.execute("LANG=C rpm -q gpg-pubkey-"..keyid.." > /dev/null 2>&1")
            if ret == 0 then
                aptwarning(_("Missing gpg key is already installed: #")..keyid)
            else
                local doimport = false
                if confget("APT::Get::Assume-Yes/b", "false") == "true" then
                    doimport = true
                else
                    io.stdout.write(io.stdout, _("Missing gpg key found").." ("..file..": #"..keyid..") ".._("Import it? [Y/n] "))
                    local answer = io.read()
                    answer = string.lower(string.sub(answer, 1, 1))
                    doimport = answer == "y" or answer == ""
                end

                if doimport then
                    local execpath = "LANG=C rpm --import "..keyspath.."/"..file
                    if quiet then
                        execpath = execpath .. " > /dev/null 2>&1"
                    end
                    if os.execute(execpath) > 0 then
                        print(_("Error importing GPG key"))
                    else
                        missings[keyid] = nil
                        keysimported = keysimported + 1
                    end
                end
            end
        end
    end

    if keysimported > 0 then
        gpgcheck(true)
    end
end

if not good then
    table.foreach(errors, showerrors)
    apterror(_("Error(s) while checking package signatures:\n"..unsigned.." unsigned package(s)\n"..missing.." package(s) with missing signatures\n"..illegal.." package(s) with illegal/corrupted signatures\n"..unknown.." unknown error(s)"))
end

-- vim::sts=4:sw=4
