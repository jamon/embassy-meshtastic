fn main() {
    // build the meshtastic protobufs using femtopb

    femtopb_build::Config::new()
        .protos(&["protobufs/meshtastic/mesh.proto", "protobufs/meshtastic/deviceonly.proto"])
        .includes(&["protobufs"])
        .derive_defmt(cfg!(feature = "defmt"))
        .compile()
        .unwrap();
    // femtopb_build::Config::new()
    //     .protos(&["protobufs/meshtastic/deviceonly.proto"])
    //     .includes(&["protobufs"])
    //     .derive_defmt(cfg!(feature = "defmt"))
    //     .compile()
    //     .unwrap();
    // femtopb_build::compile_protos(
    //     &["protobufs/meshtastic/mesh.proto"],
    //     &["protobufs"]
    // ).unwrap();
}
