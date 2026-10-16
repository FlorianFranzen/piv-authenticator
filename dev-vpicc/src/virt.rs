//! Virtual trussed client (mostly for testing)

pub mod dispatch {

    use trussed::{
        backend::{Backend as _, BackendId},
        platform::Platform,
        serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl},
        service::ServiceResources,
        types::Context,
    };
    use trussed_auth::AuthExtension;
    use trussed_auth_backend::{AuthBackend, AuthContext, FilesystemLayout, MAX_HW_KEY_LEN};
    use trussed_chunked::ChunkedExtension;
    use trussed_core::{
        Error,
        api::{Reply, Request, reply, request},
        types::{Bytes, Location},
    };
    use trussed_hpke::HpkeExtension;
    use trussed_rsa_alloc::SoftwareRsa;
    use trussed_staging::{StagingBackend, StagingContext};
    use trussed_wrap_key_to_file::WrapKeyToFileExtension;

    /// Backends used by opcard
    pub const BACKENDS: &[BackendId<Backend>] = &[
        BackendId::Custom(Backend::Staging),
        BackendId::Custom(Backend::Auth),
        BackendId::Custom(Backend::Rsa),
        BackendId::Core,
    ];

    #[derive(Debug, Clone, Copy)]
    pub enum Backend {
        Auth,
        Rsa,
        Staging,
    }

    #[derive(Debug, Clone, Copy)]
    pub enum Extension {
        Auth,
        Chunked,
        Hpke,
        WrapKeyToFile,
    }

    impl From<Extension> for u8 {
        fn from(extension: Extension) -> Self {
            match extension {
                Extension::Auth => 0,
                Extension::Chunked => 1,
                Extension::Hpke => 2,
                Extension::WrapKeyToFile => 3,
            }
        }
    }

    impl TryFrom<u8> for Extension {
        type Error = Error;

        fn try_from(id: u8) -> Result<Self, Self::Error> {
            match id {
                0 => Ok(Extension::Auth),
                1 => Ok(Extension::Chunked),
                2 => Ok(Extension::Hpke),
                3 => Ok(Extension::WrapKeyToFile),
                _ => Err(Error::InternalError),
            }
        }
    }

    /// Dispatch implementation with the backends required by opcard
    #[derive(Debug)]
    pub struct Dispatch {
        auth: AuthBackend,
        staging: StagingBackend,
    }

    /// Dispatch context for the backends required by opcard
    #[derive(Default)]
    pub struct DispatchContext {
        auth: AuthContext,
        staging: StagingContext,
    }

    impl Dispatch {
        pub fn new() -> Self {
            Self {
                auth: AuthBackend::new(Location::Internal, FilesystemLayout::V0),
                staging: StagingBackend::new(),
            }
        }

        pub fn with_hw_key(hw_key: Bytes<MAX_HW_KEY_LEN>) -> Self {
            Self {
                auth: AuthBackend::with_hw_key(Location::Internal, hw_key, FilesystemLayout::V0),
                staging: StagingBackend::new(),
            }
        }
    }

    impl Default for Dispatch {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ExtensionDispatch for Dispatch {
        type BackendId = Backend;
        type Context = DispatchContext;
        type ExtensionId = Extension;

        fn core_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            ctx: &mut Context<Self::Context>,
            request: &Request,
            resources: &mut ServiceResources<P>,
        ) -> Result<Reply, Error> {
            match backend {
                Backend::Auth => {
                    self.auth
                        .request(&mut ctx.core, &mut ctx.backends.auth, request, resources)
                }
                Backend::Staging => self.staging.request(
                    &mut ctx.core,
                    &mut ctx.backends.staging,
                    request,
                    resources,
                ),
                Backend::Rsa => SoftwareRsa.request(&mut ctx.core, &mut (), request, resources),
            }
        }

        fn extension_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            extension: &Self::ExtensionId,
            ctx: &mut Context<Self::Context>,
            request: &request::SerdeExtension,
            resources: &mut ServiceResources<P>,
        ) -> Result<reply::SerdeExtension, Error> {
            match backend {
                Backend::Auth => match extension {
                    Extension::Auth => self.auth.extension_request_serialized(
                        &mut ctx.core,
                        &mut ctx.backends.auth,
                        request,
                        resources,
                    ),
                    Extension::Chunked|Extension::Hpke|Extension::WrapKeyToFile => Err(Error::RequestNotAvailable),
                }
                Backend::Staging =>match extension {
                    Extension::Chunked => {
                        <StagingBackend as ExtensionImpl<ChunkedExtension>>::extension_request_serialized(
                            &mut self.staging,
                            &mut ctx.core,
                            &mut ctx.backends.staging,
                            request,
                            resources
                        )
                    }
                    Extension::Hpke => {
                        <StagingBackend as ExtensionImpl<HpkeExtension>>::extension_request_serialized(
                            &mut self.staging,
                            &mut ctx.core,
                            &mut ctx.backends.staging,
                            request,
                            resources
                        )
                    }
                    Extension::WrapKeyToFile => {
                        <StagingBackend as ExtensionImpl<WrapKeyToFileExtension>>::extension_request_serialized(
                            &mut self.staging,
                            &mut ctx.core,
                            &mut ctx.backends.staging,
                            request,
                            resources
                        )
                    }
                    Extension::Auth => Err(Error::RequestNotAvailable),
                }
                Backend::Rsa => Err(Error::RequestNotAvailable),
            }
        }
    }

    impl ExtensionId<AuthExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Auth;
    }
    impl ExtensionId<ChunkedExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Chunked;
    }
    impl ExtensionId<HpkeExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Hpke;
    }
    impl ExtensionId<WrapKeyToFileExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::WrapKeyToFile;
    }
}

use std::path::PathBuf;
use trussed::platform::{Platform as _, UserInterface};
use trussed::virt::{self, Client, StorageConfig, StoreConfig};
use trussed_core::types::{Bytes, consent};

/// Names a file that decides user presence, for tests that need a touch to be refused
///
/// Unset, every presence check is granted, as before. Set, the file is read on every check:
/// `deny` refuses (the request then waits out its timeout, as on a token nobody touches),
/// anything else or a missing file grants.
pub const USER_PRESENCE_ENV: &str = "VPICC_USER_PRESENCE";

/// User presence as the file named by [`USER_PRESENCE_ENV`] says
struct FileUserPresence(PathBuf);

impl UserInterface for FileUserPresence {
    fn check_user_presence(&mut self) -> consent::Level {
        match std::fs::read_to_string(&self.0) {
            Ok(answer) if answer.trim() == "deny" => consent::Level::None,
            _ => consent::Level::Normal,
        }
    }
}

/// Client type using a dispatcher with the backends required by opcard
pub type VirtClient<'a> = Client<'a, dispatch::Dispatch>;

/// Run a client using a provided store
pub fn with_client<R, F>(store: StoreConfig, client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
{
    #[allow(clippy::unwrap_used)]
    virt::with_platform(store, |mut platform| {
        if let Some(path) = std::env::var_os(USER_PRESENCE_ENV) {
            platform
                .user_interface()
                .set_inner(Box::new(FileUserPresence(path.into())));
        }
        platform.run_client_with_backends(
            client_id,
            dispatch::Dispatch::with_hw_key(Bytes::from(b"some bytes")),
            dispatch::BACKENDS,
            f,
        )
    })
}

/// Run the backend with the extensions required by opcard
/// using storage backed by a file
pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
    P: Into<PathBuf>,
{
    let store = StoreConfig {
        internal: StorageConfig::filesystem(internal.into()),
        external: StorageConfig::ram(),
        volatile: StorageConfig::ram(),
    };
    with_client(store, client_id, f)
}

/// Run the backend with the extensions required by opcard
/// using a RAM file storage
pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
{
    with_client(StoreConfig::ram(), client_id, f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_decides_user_presence() {
        let path = std::env::temp_dir().join(format!("vpicc-up-{}", std::process::id()));
        let mut presence = FileUserPresence(path.clone());
        assert_eq!(presence.check_user_presence(), consent::Level::Normal);
        std::fs::write(&path, "deny\n").unwrap();
        assert_eq!(presence.check_user_presence(), consent::Level::None);
        std::fs::write(&path, "grant").unwrap();
        assert_eq!(presence.check_user_presence(), consent::Level::Normal);
        std::fs::remove_file(&path).unwrap();
    }
}
