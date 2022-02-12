local saz = {}
local compressors = {}
local crypt = {}
local saz_hdr = "c3Bc7H"
local function add_compressor(comp, library, read, write)
	local ok, res = pcall(require, library)
	compressors[comp] = {
		lib = lib,
		r = read,
		w = write
	}
end

add_compressor("lz4", "lz4", function(lib, state)

end)
--add_compressor("lz4", "lz4")