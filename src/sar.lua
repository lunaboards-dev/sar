local sar = {}

local stat = require("posix.sys.stat")
local unistd = require("posix.unistd")
local xxh64 = require("xxh64")

local se, smag = "<", "sar"
if string.unpack("H", "\xaa\x55") == 0xaa55 then
	se, smag = ">", "ras"
end

local sec_hdr = "c3BHIIl"
local saz_hdr = "c3Bc7H"
local sec_foot = "c10II"
local ent_wrap = "lHHHH"
local file_ent = "llHHllH"
local footer_ent = "llHH"
local tag = "HH"

local function epack(e, pack, ...)
	return string.pack(e..pack, ...)
end

local function eupack(e, pack, ...)
	return string.unpack(e..pack, ...)
end

local function tag(e, k, v)
	return epack(e, tag, #k, #v)..k..v
end

local minorbits = 20
local minormask = (1 << minorbits) - 1
local function dev(d)
	return d >> minorbits, d & minormask
end

local function sar_stat(flist)
	local slist = {}
	for i=1, #flist do
		local s = stat.lstat(flist[i])
		slist[i] = {
			dev = s.st_dev,
			ino = s.st_ino,
			mode = s.st_mode,
			nlink = s.st_nlink,
			uid = s.st_uid,
			gid = s.st_gid,
			rdev = s.st_rdev,
			size = s.st_size,
			atime = s.st_atime,
			mtime = s.st_mtime,
			ctime = s.st_ctime,
			blksize = s.st_blksize,
			blocks = s.st_blocks,
			name = flist[i]
		}
	end
	return slist
end

local function sar_writeheader(ofi, files)
	local fent = {}
	local off = 0
	for i=1, #files do
		local f = files[i]
		local tags = ""
		local tagc = 0
		local flags = 0
		if f.uid >> 16 > 0 then
			tags = tags .. tag(se, "u16:uid-hi", epack(se, "H", f.uid >> 16))
			tagc = tagc + 1
		end
		if f.gid >> 16 > 0 then
			tags = tags .. tag(se, "u16:gid-hi", epack(se, "H", f.gid >> 16))
			tagc = tagc + 1
		end
		local ft = f.mode >> 12
		f.ft = ft
		if ft == 2 or ft == 6 then
			tags = tags .. tag(se, "octet:rdevinfo", epack(se, "II", dev(f.rdev)))
			tagc = tagc + 1
		elseif ft == 10 then
			f.cont = unistd.readlink(f.name)
			f.size = #f.size
		elseif ft ~= 8 then
			f.size = 0
			flags = 2
		end
		local hdr = epack(se, file_ent, f.size, off, f.uid & 0xFFFF, f.gid & 0xFFFF, f.atime, f.mtime, #f.name)..f.name
		off = off + f.size
		hdr = epack(se, ent_wrap, i-1, #hdr, flags, tagc, f.mode)..hdr
		table.insert(fent, hdr)
	end
	local hdat = table.concat(fent)
	ofi:write((epack(se, sec_hdr, smag, 0, 0, #hdat, #fent, off)),hdat)
end

local pfx = {"bytes", "KiB", "MiB", "GiB", "TiB"}
local function to_human(i)
	local s = 1
	while i >= 1024 and pfx[s+1] do
		i = i / 1024
		s = s + 1
	end
	return string.format("%.1f %s", i, pfx[s])
end

local function xxhwrite(ofi, state, dat, stat)
	stat.ramt = (stat.ramt or 0) + #dat
	if not _QUIET then
		io.stderr:write(string.format("\r\27[K%s (%s/%s)", stat.name, to_human(stat.ramt), to_human(stat.size)))
	end
	--io.stdout:write(".")
	state:update(dat)
	ofi:write(dat)
end

local function sar_writefiles(ofi, files)
	local state = xxh64.state()
	for i=1, #files do
		state:reset()
		local f = files[i]
		--io.stderr:write(f.name)
		if f.cont then
			xxhwrite(ofi, state, f.cont)
			f.sum = state:digest()
		else
			local fh = io.open(f.name, "rb")
			while true do
				local chunk = fh:read(_BLOCKSIZE)
				if not chunk or #chunk == 0 then break end
				xxhwrite(ofi, state, chunk, f)
			end
			io.stderr:write("\n")
			fh:close()
			f.sum = state:digest()
		end
		--print("")
	end
end

local function sar_writefooter(ofi, files)
	local fent = {}
	for i=1, #files do
		local fsum = files[i].sum
		if fsum then
			table.insert(fent, (epack(se, footer_ent, i-1, fsum, 0, 0)))
		end
	end
	local fdat = table.concat(fent)
	ofi:write((epack(se, sec_foot, "TRAILER!!!", #files, #fdat)), fdat)
end
--[[
function sar.create_saz(output, files, compression)
	
end
]]

function sar.create(output, files)
	local flist = sar_stat(files)
	sar_writeheader(output, flist)
	sar_writefiles(output, flist)
	sar_writefooter(output, flist)
end

local arc = {}

local tagtypes = {
	u8 = "B",
	u16 = "H",
	u32 = "I",
	u64 = "L",
	s8 = "b",
	s16 = "h",
	u32 = "i",
	s64 = "l",
	bool = function(e, v)
		return sunpack(e, "B", v) ~= 0
	end,
	octet = function(e, v)
		return v
	end,
	str = function(e, v)
		return v
	end
}

local taghooks = {
	["u16:uid-hi"] = function(ent, tv)
		ent.uid = ent.uid | (tv << 16)
	end,
	["u16:gid-hi"] = function(ent, tv)
		ent.gid = ent.gid | (tv << 16)
	end,
	["str:user"] = function(ent, tv)

	end,
	["str:group"] = function(ent, tv)

	end,
	["octet:devinfo"] = function(ent, tv, e)
		ent.dev_maj, ent.dev_min = eunpack(e, "II", tv)
	end,
	["octet:rdevinfo"] = function(ent, tv, e)
		ent.rdev_maj, ent.rdev_min = eunpack(e, "II", tv)
	end
}

local function xpread(str ,inst, amt)
	local par = inst
	while par do
		par.ramt = par.ramt + amt
		if par.ramt > par.hsize then
			error("unexpected end of header")
		end
		par = par.parent
	end
	local dat = str:read(amt)
	if not dat or #dat ~= amt then
		error("unexpected eof")
	end
	return dat
end

local function readtags(fh, ent, einst, tagc)
	for i=1, tagc do
		local ks, vs = eupack(fh.e, tag, xpread(fh.s, einst, tag:packsize()))
		local key = xpread(fh.s, einst, ks)
		local vraw = xpread(fh.s, einst, vs)
		local ttype, tname = key:match("([%w]+):([a-z%-]+)")
		local tt = tagtypes[ttype]
		if not tt then error("unknown tag type "..ttype) end
		local value
		if type(tt) == "string" then
			value = eupack(fh.e, tt, vraw)
		elseif type(tt) == "function" then
			value = tt(fh.e, vraw)
		else
			error("internal error decoding type "..ttype..": expected string or function, got "..type(tt))
		end
		local hook = taghooks[key]
		if hook then
			hook(ent, value, fh.e)
		else
			ent[tname] = value
		end
	end
end

local function sar_readmeta(fh)
	local h = fh.s:read(3)
	if h == "sar" then
		fh.e = "<"
	elseif h == "ras" then
		fh.e = ">"
	else
		error("Not a SAR archive.")
	end
	local toff = 0
	while true do
		local h, ver, sflags, hsize, ecount, bodysize = eupack(fh.e, sec_hdr, h..fh.s:read(sec_hdr:packsize()-3))
		toff = toff + hsize + sec_hdr:packsize()
		local hinst = {
			ramt = 0,
			hsize = hsize
		}
		--[[local function pread(amt) -- "Protected" read. Ensures we don't go over hsize.
			ramt = ramt + amt
			if ramt > hsize then
				error("unexpected end of header")
			end
			local dat = fh.s:read(amt)
			if not dat or #dat ~= amt then
				error("unexpected eof")
			end
			return dat
		end]]
		for i=1, ecount do
			local id, esize, flags, tagc, mode = eupack(fh.e, ent_wrap, xpread(fh.s, hinst, ent_wrap:packsize()))
			if flags & 1 > 0 then
				-- skip
				fh.e:seek("cur", hsize)
				goto continue
			end
			local einst = {
				ramt = 0,
				hsize = esize,
				parent = parent
			}
			local fsize, foff, uid, gid, atime, mtime, nsize = eupack(fh.e, file_ent, xpread(fh.s, einst, file_ent:packsize()))
			local name = xpread(fh.s, einst, nsize)
			local ent = {
				mode = mode,
				aflags = flags,
				id = id,
				size = fsize,
				offset = toff+foff,
				uid = uid,
				gid = gid,
				atime = atime,
				mtime = mtime,
				name = name
			}
			readtags(fh, ent, einst, tagc)
			table.insert(fh.ents, ent)
			fh.idmap[id] = ent
			::continue::
		end
		fh.s:seek("cur", bodysize)
		local fmark, fcount, fsize = eupack(fh.e, sec_foot, fh.s:read(sec_foot:packsize()))
		local finst = {
			hsize = fsize,
			ramt = 0
		}
		for i=1, fcount do
			local id, hash, tagc, esize = eupack(fh.e, footer_ent, xpread(fh.s, finst, footer_ent:packsize()))
			local ent = fh.idmap[id]
			ent.hash = hash
			local einst = {
				parent = finst,
				ramt = 0,
				hsize = esize
			}
			readtags(fh, ent, einst, tagc)
		end
		if sflags & 1 == 0 then break end
	end
end

function arc:get(fpath)
	if self.pathcache[fpath] then return self.pathcache[fpath] end
	for i=1, #self.ents do
		if self.ents[i].name == fpath then self.pathcache[fpath] = self.ents[i] return self.ents[i] end
	end
end

function arc:go_to(fpath)
	local e = self:get(fpath)
	self:seek("set", e.offset)
end

local arcf = {}

function arcf:read(amt)
	if self.ptr == self.ent.size then return nil end
	self.fh:seek("set", self.ent.offset+self.ptr)
	if self.ptr + amt >= self.ent.size then
		amt = self.ent.size - self.ptr
	end
	self.ptr = self.ptr + amt
	return self.fh:read(amt)
end

function arcf:seek(whence, amt)
	if whence == "cur" then
		self.ptr = self.ptr + amt
	elseif whence == "set" then
		self.ptr = amt - 1
	elseif whence == "end" then
		self.ptr = self.ent.size + amt
	end
	if self.ptr < 0 then self.ptr = 0 end
	if self.ptr > self.ent.size then self.ptr = self.ent.size end
	return self.ptr+1
end

function arc:open(fpath) -- soon
	local e = self:get(fpath)
	if not e then return nil, "not found" end
	return setmetatable({
		ptr = 0,
		ent = e,
		fh = self
	}, {__index=arcf})
end

function arc:verify(fpath_or_id)
	local ent
	--print("FPATH", fpath_or_id)
	if type(fpath_or_id) == "string" then
		ent = self:get(fpath_or_id)
	else
		ent = self.idmap[fpath_or_id]
	end
	if not ent then error("not found") end
	if ent.aflags & 2 > 0 then return true end
	self.xxh:reset()
	self:seek("set", ent.offset)
	local size = ent.size
	while size > 0 do
		local csize = _BLOCKSIZE
		if csize > size then
			csize = size
		end
		local data = self:read(csize)
		size = size - csize
		self.xxh:update(data)
	end
	local hash = self.xxh:digest()
	return ent.hash == hash, ent.hash, hash
end

function arc:read(amt)
	return self.s:read(amt)
end

function arc:seek(whence, amt)
	return self.s:seek(whence, amt)
end

function arc:files()
	local i = 0
	return function()
		i = i + 1
		return self.ents[i]
	end
end

function sar.open(fstream)
	local fh = {
		s = fstream,
		ents = {},
		idmap = {},
		pathcache = {},
		xxh = xxh64.state()
	}
	setmetatable(fh, {__index=arc})
	sar_readmeta(fh)
	return fh
end

return sar