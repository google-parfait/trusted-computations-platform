// Copyright 2024 The Trusted Computations Platform Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::session::{OakClientSession, OakServerSession};
use anyhow::{anyhow, Result};
use oak_proto_rust::oak::session::v1::{
    session_request::Request, session_response::Response, SessionRequest, SessionResponse,
};
use tcp_proto::runtime::endpoint::Payload;

// Encryptor trait responsible for encrypting/decrypting messages between TCP
// replicas after handshake has successfully completed.
pub trait Encryptor {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Payload>;

    fn decrypt(&mut self, payload: &Payload) -> Result<Vec<u8>>;
}

// Default implementations for Encryptor trait.
pub struct DefaultClientEncryptor {
    session: Box<dyn OakClientSession>,
}

impl DefaultClientEncryptor {
    pub fn new(session: Box<dyn OakClientSession>) -> Self {
        Self { session }
    }
}

impl Encryptor for DefaultClientEncryptor {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Payload> {
        self.session.write(plaintext)?;
        if let Some(session_request) = self.session.get_outgoing_message()?
            && let Some(Request::Ciphertext(ciphertext)) = session_request.request
        {
            Ok(Payload {
                contents: ciphertext.into(),
                ..Default::default()
            })
        } else {
            Err(anyhow!("No outgoing ciphertext message retrieved."))
        }
    }

    fn decrypt(&mut self, payload: &Payload) -> Result<Vec<u8>> {
        let response = SessionResponse {
            response: Some(Response::Ciphertext(payload.contents.to_vec())),
        };
        self.session.put_incoming_message(&response)?;
        let plaintext = self.session.read()?;
        if plaintext.is_none() {
            return Err(anyhow!("No decrypted text found for the ciphertext."));
        }
        Ok(plaintext.unwrap())
    }
}

pub struct DefaultServerEncryptor {
    session: Box<dyn OakServerSession>,
}

impl DefaultServerEncryptor {
    pub fn new(session: Box<dyn OakServerSession>) -> Self {
        Self { session }
    }
}

impl Encryptor for DefaultServerEncryptor {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Payload> {
        self.session.write(plaintext)?;
        if let Some(session_response) = self.session.get_outgoing_message()?
            && let Some(Response::Ciphertext(ciphertext)) = session_response.response
        {
            Ok(Payload {
                contents: ciphertext.into(),
                ..Default::default()
            })
        } else {
            Err(anyhow!("No outgoing ciphertext message retrieved."))
        }
    }

    fn decrypt(&mut self, payload: &Payload) -> Result<Vec<u8>> {
        let request = SessionRequest {
            request: Some(Request::Ciphertext(payload.contents.to_vec())),
        };
        self.session.put_incoming_message(&request)?;
        let plaintext = self.session.read()?;
        if plaintext.is_none() {
            return Err(anyhow!("No decrypted text found for the ciphertext."));
        }
        Ok(plaintext.unwrap())
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    extern crate mockall;
    use self::mockall::predicate::eq;
    use crate::encryptor::{DefaultClientEncryptor, DefaultServerEncryptor, Encryptor};
    use crate::mock::{MockOakClientSession, MockOakServerSession};
    use anyhow::{anyhow, Result};
    use core::mem;
    use oak_proto_rust::oak::session::v1::{
        session_request::Request, session_response::Response, AttestRequest, AttestResponse,
        SessionRequest, SessionResponse,
    };
    use prost::bytes::Bytes;
    use tcp_proto::runtime::endpoint::Payload;

    struct OakClientSessionBuilder {
        mock_oak_client_session: MockOakClientSession,
    }

    impl OakClientSessionBuilder {
        fn new() -> OakClientSessionBuilder {
            OakClientSessionBuilder {
                mock_oak_client_session: MockOakClientSession::new(),
            }
        }

        fn expect_get_outgoing_message(
            mut self,
            message: Result<Option<SessionRequest>>,
        ) -> OakClientSessionBuilder {
            self.mock_oak_client_session
                .expect_get_outgoing_message()
                .once()
                .return_once(move || message);
            self
        }

        fn expect_put_incoming_message(
            mut self,
            message: SessionResponse,
            result: Result<Option<()>>,
        ) -> OakClientSessionBuilder {
            self.mock_oak_client_session
                .expect_put_incoming_message()
                .with(eq(message))
                .once()
                .return_once(move |_| result);
            self
        }

        fn expect_write(
            mut self,
            plaintext: Bytes,
            result: anyhow::Result<()>,
        ) -> OakClientSessionBuilder {
            self.mock_oak_client_session
                .expect_write()
                .with(eq(plaintext))
                .once()
                .return_once(move |_| result);
            self
        }

        fn expect_read(
            mut self,
            result: anyhow::Result<Option<Vec<u8>>>,
        ) -> OakClientSessionBuilder {
            self.mock_oak_client_session
                .expect_read()
                .once()
                .return_once(move || result);
            self
        }

        fn take(mut self) -> MockOakClientSession {
            mem::take(&mut self.mock_oak_client_session)
        }
    }

    struct OakServerSessionBuilder {
        mock_oak_server_session: MockOakServerSession,
    }

    impl OakServerSessionBuilder {
        fn new() -> OakServerSessionBuilder {
            OakServerSessionBuilder {
                mock_oak_server_session: MockOakServerSession::new(),
            }
        }

        fn expect_get_outgoing_message(
            mut self,
            message: Result<Option<SessionResponse>>,
        ) -> OakServerSessionBuilder {
            self.mock_oak_server_session
                .expect_get_outgoing_message()
                .once()
                .return_once(move || message);
            self
        }

        fn expect_put_incoming_message(
            mut self,
            message: SessionRequest,
            result: Result<Option<()>>,
        ) -> OakServerSessionBuilder {
            self.mock_oak_server_session
                .expect_put_incoming_message()
                .with(eq(message))
                .once()
                .return_once(move |_| result);
            self
        }

        fn expect_write(
            mut self,
            plaintext: Bytes,
            result: anyhow::Result<()>,
        ) -> OakServerSessionBuilder {
            self.mock_oak_server_session
                .expect_write()
                .with(eq(plaintext))
                .once()
                .return_once(move |_| result);
            self
        }

        fn expect_read(
            mut self,
            result: anyhow::Result<Option<Vec<u8>>>,
        ) -> OakServerSessionBuilder {
            self.mock_oak_server_session
                .expect_read()
                .once()
                .return_once(move || result);
            self
        }

        fn take(mut self) -> MockOakServerSession {
            mem::take(&mut self.mock_oak_server_session)
        }
    }

    fn create_session_request(ciphertext: Bytes) -> SessionRequest {
        SessionRequest {
            request: Some(Request::Ciphertext(ciphertext.to_vec())),
        }
    }

    fn create_session_response(ciphertext: Bytes) -> SessionResponse {
        SessionResponse {
            response: Some(Response::Ciphertext(ciphertext.to_vec())),
        }
    }

    #[test]
    fn test_client_encrypt_success() {
        let plaintext: &[u8] = b"plaintext";
        let ciphertext: &[u8] = b"ciphertext";
        let session_request = create_session_request(ciphertext.into());
        let mock_oak_client_session = OakClientSessionBuilder::new()
            .expect_write(plaintext.into(), Ok(()))
            .expect_get_outgoing_message(Ok(Some(session_request)))
            .take();
        let mut encryptor = DefaultClientEncryptor::new(Box::new(mock_oak_client_session));

        assert_eq!(
            ciphertext.to_vec(),
            encryptor.encrypt(plaintext).unwrap().contents
        );
    }

    #[test]
    fn test_client_encryptor_write_error() {
        let plaintext: &[u8] = b"plaintext";
        let mock_oak_client_session = OakClientSessionBuilder::new()
            .expect_write(plaintext.into(), Err(anyhow!("Err")))
            .take();
        let mut encryptor = DefaultClientEncryptor::new(Box::new(mock_oak_client_session));

        assert!(encryptor.encrypt(plaintext).is_err());
    }

    #[test]
    fn test_client_encryptor_get_outgoing_message_error() {
        let plaintext: &[u8] = b"plaintext";
        let mock_oak_client_session = OakClientSessionBuilder::new()
            .expect_write(plaintext.into(), Ok(()))
            .expect_get_outgoing_message(Err(anyhow!("Err")))
            .take();
        let mut encryptor = DefaultClientEncryptor::new(Box::new(mock_oak_client_session));

        assert!(encryptor.encrypt(plaintext).is_err());
    }

    #[test]
    fn test_client_encryptor_get_outgoing_message_invalid() {
        let plaintext: &[u8] = b"plaintext";
        let invalid_message = SessionRequest {
            request: Some(Request::AttestRequest(AttestRequest::default())),
        };
        let mock_oak_client_session = OakClientSessionBuilder::new()
            .expect_write(plaintext.into(), Ok(()))
            .expect_get_outgoing_message(Ok(Some(invalid_message)))
            .take();
        let mut encryptor = DefaultClientEncryptor::new(Box::new(mock_oak_client_session));

        assert!(encryptor.encrypt(plaintext).is_err());
    }

    #[test]
    fn test_client_decrypt_success() {
        let plaintext: &[u8] = b"plaintext";
        let ciphertext: &[u8] = b"ciphertext";
        let payload = Payload {
            contents: ciphertext.into(),
            ..Default::default()
        };
        let session_response = create_session_response(ciphertext.into());
        let mock_oak_client_session = OakClientSessionBuilder::new()
            .expect_put_incoming_message(session_response, Ok(Some(())))
            .expect_read(Ok(Some(plaintext.into())))
            .take();
        let mut encryptor = DefaultClientEncryptor::new(Box::new(mock_oak_client_session));

        assert_eq!(plaintext.to_vec(), encryptor.decrypt(&payload).unwrap());
    }

    #[test]
    fn test_client_decryptor_put_incoming_message_error() {
        let ciphertext: &[u8] = b"ciphertext";
        let payload = Payload {
            contents: ciphertext.into(),
            ..Default::default()
        };
        let session_response = create_session_response(ciphertext.into());
        let mock_oak_client_session = OakClientSessionBuilder::new()
            .expect_put_incoming_message(session_response, Err(anyhow!("Err")))
            .take();
        let mut encryptor = DefaultClientEncryptor::new(Box::new(mock_oak_client_session));

        assert!(encryptor.decrypt(&payload).is_err());
    }

    #[test]
    fn test_client_decryptor_read_error() {
        let ciphertext: &[u8] = b"ciphertext";
        let payload = Payload {
            contents: ciphertext.into(),
            ..Default::default()
        };
        let session_response = create_session_response(ciphertext.into());
        let mock_oak_client_session = OakClientSessionBuilder::new()
            .expect_put_incoming_message(session_response, Ok(Some(())))
            .expect_read(Err(anyhow!("Err")))
            .take();
        let mut encryptor = DefaultClientEncryptor::new(Box::new(mock_oak_client_session));

        assert!(encryptor.decrypt(&payload).is_err());
    }

    #[test]
    fn test_client_decryptor_read_none() {
        let ciphertext: &[u8] = b"ciphertext";
        let payload = Payload {
            contents: ciphertext.into(),
            ..Default::default()
        };
        let session_response = create_session_response(ciphertext.into());
        let mock_oak_client_session = OakClientSessionBuilder::new()
            .expect_put_incoming_message(session_response, Ok(Some(())))
            .expect_read(Ok(None))
            .take();
        let mut encryptor = DefaultClientEncryptor::new(Box::new(mock_oak_client_session));

        assert!(encryptor.decrypt(&payload).is_err());
    }

    #[test]
    fn test_server_encrypt_success() {
        let plaintext: &[u8] = b"plaintext";
        let ciphertext: &[u8] = b"ciphertext";
        let session_response = create_session_response(ciphertext.into());
        let mock_oak_server_session = OakServerSessionBuilder::new()
            .expect_write(plaintext.into(), Ok(()))
            .expect_get_outgoing_message(Ok(Some(session_response)))
            .take();
        let mut encryptor = DefaultServerEncryptor::new(Box::new(mock_oak_server_session));

        assert_eq!(
            ciphertext.to_vec(),
            encryptor.encrypt(plaintext).unwrap().contents
        );
    }

    #[test]
    fn test_server_encryptor_write_error() {
        let plaintext: &[u8] = b"plaintext";
        let mock_oak_server_session = OakServerSessionBuilder::new()
            .expect_write(plaintext.into(), Err(anyhow!("Err")))
            .take();
        let mut encryptor = DefaultServerEncryptor::new(Box::new(mock_oak_server_session));

        assert!(encryptor.encrypt(plaintext).is_err());
    }

    #[test]
    fn test_server_encryptor_get_outgoing_message_error() {
        let plaintext: &[u8] = b"plaintext";
        let mock_oak_server_session = OakServerSessionBuilder::new()
            .expect_write(plaintext.into(), Ok(()))
            .expect_get_outgoing_message(Err(anyhow!("Err")))
            .take();
        let mut encryptor = DefaultServerEncryptor::new(Box::new(mock_oak_server_session));

        assert!(encryptor.encrypt(plaintext).is_err());
    }

    #[test]
    fn test_server_encryptor_get_outgoing_message_invalid() {
        let plaintext: &[u8] = b"plaintext";
        let invalid_message = SessionResponse {
            response: Some(Response::AttestResponse(AttestResponse::default())),
        };
        let mock_oak_server_session = OakServerSessionBuilder::new()
            .expect_write(plaintext.into(), Ok(()))
            .expect_get_outgoing_message(Ok(Some(invalid_message)))
            .take();
        let mut encryptor = DefaultServerEncryptor::new(Box::new(mock_oak_server_session));

        assert!(encryptor.encrypt(plaintext).is_err());
    }

    #[test]
    fn test_server_decrypt_success() {
        let plaintext: &[u8] = b"plaintext";
        let ciphertext: &[u8] = b"ciphertext";
        let payload = Payload {
            contents: ciphertext.into(),
            ..Default::default()
        };
        let session_request = create_session_request(ciphertext.into());
        let mock_oak_server_session = OakServerSessionBuilder::new()
            .expect_put_incoming_message(session_request, Ok(Some(())))
            .expect_read(Ok(Some(plaintext.into())))
            .take();
        let mut encryptor = DefaultServerEncryptor::new(Box::new(mock_oak_server_session));

        assert_eq!(plaintext.to_vec(), encryptor.decrypt(&payload).unwrap());
    }

    #[test]
    fn test_server_decryptor_put_incoming_message_error() {
        let ciphertext: &[u8] = b"ciphertext";
        let payload = Payload {
            contents: ciphertext.into(),
            ..Default::default()
        };
        let session_request = create_session_request(ciphertext.into());
        let mock_oak_server_session = OakServerSessionBuilder::new()
            .expect_put_incoming_message(session_request, Err(anyhow!("Err")))
            .take();
        let mut encryptor = DefaultServerEncryptor::new(Box::new(mock_oak_server_session));

        assert!(encryptor.decrypt(&payload).is_err());
    }

    #[test]
    fn test_server_decryptor_read_error() {
        let ciphertext: &[u8] = b"ciphertext";
        let payload = Payload {
            contents: ciphertext.into(),
            ..Default::default()
        };
        let session_request = create_session_request(ciphertext.into());
        let mock_oak_server_session = OakServerSessionBuilder::new()
            .expect_put_incoming_message(session_request, Ok(Some(())))
            .expect_read(Err(anyhow!("Err")))
            .take();
        let mut encryptor = DefaultServerEncryptor::new(Box::new(mock_oak_server_session));

        assert!(encryptor.decrypt(&payload).is_err());
    }

    #[test]
    fn test_server_decryptor_read_none() {
        let ciphertext: &[u8] = b"ciphertext";
        let payload = Payload {
            contents: ciphertext.into(),
            ..Default::default()
        };
        let session_request = create_session_request(ciphertext.into());
        let mock_oak_server_session = OakServerSessionBuilder::new()
            .expect_put_incoming_message(session_request, Ok(Some(())))
            .expect_read(Ok(None))
            .take();
        let mut encryptor = DefaultServerEncryptor::new(Box::new(mock_oak_server_session));

        assert!(encryptor.decrypt(&payload).is_err());
    }
}
