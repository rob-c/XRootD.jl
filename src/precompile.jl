# Precompilation workload. The wire codecs and type conversions run for
# real (they are pure); the socket-bound Session/Client paths are compiled
# via `precompile` so a session's first operation doesn't pay multi-second
# JIT latency (observed: a 13-byte copy cost 4.4s of first-call compilation).

using PrecompileTools: @setup_workload, @compile_workload

@setup_workload begin
    fh = (0x00, 0x00, 0x00, 0x01)
    @compile_workload begin
        for req in (
            Wire.ProtocolRequest(),
            Wire.LoginRequest("u"),
            Wire.AuthRequest("unix", UInt8[]),
            Wire.PingRequest(),
            Wire.StatRequest("/p"),
            Wire.DirlistRequest("/p"),
            Wire.MkdirRequest("/p"),
            Wire.RmRequest("/p"),
            Wire.RmdirRequest("/p"),
            Wire.MvRequest("/a", "/b"),
            Wire.ChmodRequest("/p", UInt16(0o644)),
            Wire.TruncateRequest("/p", 0),
            Wire.LocateRequest("/p"),
            Wire.QueryRequest(Wire.kXR_QStats, "a"),
            Wire.OpenRequest("/p"; options=Wire.kXR_open_read),
            Wire.ReadRequest(fh, Int64(0), Int32(1)),
            Wire.WriteRequest(fh, Int64(0), UInt8[0x00]),
            Wire.CloseRequest(fh),
            Wire.SyncRequest(fh),
            Wire.PgReadRequest(fh, Int64(0), Int32(1)),
            Wire.PgWriteRequest(fh, Int64(0), UInt8[0x00]),
            Wire.ReadVRequest([(; fhandle=fh, offset=Int64(0), rlen=Int32(1))]),
            Wire.WriteVRequest([(; fhandle=fh, offset=Int64(0), data=UInt8[0x00])]),
        )
            Wire.encode(req, UInt16(1))
        end
        Wire.decode_header(zeros(UInt8, 8))
        Wire.parse_stat_line("1 2 51 4 5 6 0644 o g")
        Wire.parse_dirlist(Vector{UInt8}(codeunits("a\nb\0")))
        Wire.parse_locate(Vector{UInt8}(codeunits("Sr[::1]:1094")))
        Wire.parse_readv(UInt8[])
        Wire.decode_error(vcat(zeros(UInt8, 4), UInt8[0x78]))
        Wire.decode_login(zeros(UInt8, 16))
        Wire.decode_protocol(zeros(UInt8, 8))
        Wire.decode_open(zeros(UInt8, 12))
        Wire.decode_pages(Wire.encode_pages(UInt8[0x01, 0x02], Int64(0)), Int64(0))
        XrdCl.StatInfo("1 2 51 4")
        XrdCl.symbolic_mode("0644")
        sprint(show, XrdCl.XRootDStatus())
    end

    # Socket-bound paths: compile without executing.
    precompile(Session.connect, (String, Int))
    precompile(Session.reader_loop, (Session.Connection,))
    precompile(Session.read_frame, (Sockets.TCPSocket,))
    precompile(XrdCl.connection!, (XrdCl.FileSystem,))
    precompile(Base.copy, (XrdCl.FileSystem, String, String))
    for R in (
        Wire.ProtocolRequest,
        Wire.PingRequest,
        Wire.StatRequest,
        Wire.DirlistRequest,
        Wire.MkdirRequest,
        Wire.RmRequest,
        Wire.RmdirRequest,
        Wire.MvRequest,
        Wire.ChmodRequest,
        Wire.TruncateRequest,
        Wire.LocateRequest,
        Wire.QueryRequest,
        Wire.OpenRequest,
        Wire.ReadRequest,
        Wire.WriteRequest,
        Wire.CloseRequest,
        Wire.SyncRequest,
        Wire.PgReadRequest,
        Wire.ReadVRequest,
        Wire.WriteVRequest,
    )
        precompile(Session.roundtrip, (Session.Connection, R))
        precompile(XrdCl.perform, (XrdCl.FileSystem, R))
    end
end
