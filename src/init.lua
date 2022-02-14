local sar = require("sar")
--local f = io.open(arg[1], "wb")
local files = {}
local parser = require("argparse")("sar", "Sam's Archive, a simple random access archive utility.")
parser:mutex(
	parser:flag("-c --create", "Create an SAR archive."),
	parser:flag("-x --extract", "Extract files."),
	parser:flag("-u --unpack", "Extract all files from the archive."),
	parser:flag("-t --list", "List all files in the directory."),
	parser:flag("-a --append", "Append to the archive."),
	parser:flag("-i --file-info", "Show file info"),
	parser:flag("-C --check-file", "Check files")
)
parser:flag("-S --from-stdin", "Get file list from the standard input.")
parser:flag("-s --to-stdout", "Print file to stdout.")
parser:flag("-R --perserve-relative", "Preserve relative file paths.")
parser:option("-f --file", "Specifies a file to act on."):count "*"
parser:flag("-q --quiet", "Don't print to stderr.")
parser:option("-B --block-size", "Set block size in KiB"):default("1024"):convert(tonumber)
parser:argument("archive"):args "?"
local args = parser:parse()
--[[for line in io.stdin:lines() do
	table.insert(files, line)
end]]
if args.quiet then
	_QUIET = true
end

_BLOCKSIZE = args.block_size*1024

if not (args.create or args.extract or args.unpack or args.list or args.append or args.file_info or args.check_file) then
	parser:error("must specify one of -cxutai")
end

local rename = {}
local function remove_leading(path)
	return path:gsub("^[%./]*/", "")
end

local function remove_

local files = args.file
if args.from_stdin then
	for line in io.stdin:lines() do
		table.insert(files, line)
	end
end

if args.create then
	local f
	if args.to_stdout then
		f = io.stdout
	elseif not args.archive then
		parser:error("must specify archive or -s")
	else
		f = io.open(args.archive, "wb")
	end
	sar.create(f, files)
	os.exit(0)
else
	if not args.archive then
		parser:error("missing archive")
	end
end

local f = io.open(args.archive, "rb")
local arc = sar.open(f)
if args.check_file then
	if #files == 0 then
		for file in arc:files() do
			local ok, hf, hc = arc:verify(file.name)
			--print(ok, hf, hc)
			local res = ok and "OK" or "Fail"
			local sig = ok and "=" or "~"
			if hf then
				io.stdout:write(string.format("%s: %s! (%.16x %s= %.16x)\n", file.name, res, hf, sig, hc))
			else
				io.stdout:write(string.format("%s: %s! (No checksum)\n", file.name, res))
			end
		end
	else
		for i=1, #files do
			local file = files[i]
			local ok, hf, hc = arc:verify(file)
			--print(ok, hf, hc)
			local res = ok and "OK" or "Fail"
			local sig = ok and "=" or "~"
			if hf then
				io.stdout:write(string.format("%s: %s! (%.16x %s= %.16x)\n", file, res, hf, sig, hc))
			else
				io.stdout:write(string.format("%s: %s! (No checksum)\n", file, res))
			end
		end
	end
elseif args.list then
	for file in arc:files() do
		print(file.name)
	end
end