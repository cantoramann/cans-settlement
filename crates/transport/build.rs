//! Build script for spark-sdk-transport
//!
//! Compiles Spark protocol buffers using tonic-build.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "grpc")]
    {
        // Proto files to compile for the SparkService client
        let protos = [
            "proto/spark.proto",
            "proto/common.proto",
            "proto/spark_authn.proto",
            "proto/spark_token.proto",
        ];

        // Include paths for imports
        let includes = ["proto"];

        // Configure tonic-prost-build
        //
        // Proto deduplication:
        //   Upstream spark.proto contained deprecated copies of 13 token types
        //   (TokenOutput, TokenTransaction, FreezeTokensRequest, etc.) that are
        //   authoritatively defined in spark_token.proto. We removed the deprecated
        //   copies from our vendored spark.proto so prost generates each type once.
        //   No extern_path mapping is needed: the remaining cross-package references
        //   (e.g. spark_token.proto using spark.Network) resolve correctly via
        //   prost's default super:: path rewriting.
        //
        // Clippy suppressions on generated code:
        // - large_enum_variant: Proto oneofs generate enums where variants may
        //   have significantly different sizes. Boxing is not worth the indirection
        //   cost for these types.
        // - derive_partial_eq_without_eq: Generated types derive PartialEq but not
        //   Eq due to potential float fields.
        tonic_prost_build::configure()
            // Generate client code only (we're a client, not a server)
            .build_server(false)
            .build_client(true)
            // Use bytes::Bytes for proto `bytes` fields instead of Vec<u8>.
            // When tonic receives a gRPC response as a Bytes buffer, prost can
            // sub-slice into it (O(1) ref-count) instead of copying each field
            // into a separate Vec heap allocation.
            .bytes(".")
            // Suppress clippy warnings on generated types
            .type_attribute(".", "#[allow(clippy::large_enum_variant)]")
            .type_attribute(".", "#[allow(clippy::derive_partial_eq_without_eq)]")
            // Compile with protoc
            .compile_protos(&protos, &includes)?;

        // Tell cargo to rerun if protos change
        println!("cargo:rerun-if-changed=proto/");
    }

    Ok(())
}
