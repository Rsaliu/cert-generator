use axum::http::response;
use uuid::Uuid;

use std::{cell::RefCell, default, sync::{Arc,Mutex}};

use crate::messenger::messenger::{Messenger,Message};
use tonic::transport::Channel;
use tonic::{transport::Server, Request, Response, Status};
use tokio::runtime::Runtime;
use email_proto::email_sender_client::{EmailSenderClient};
use email_proto::{EmailSendRequest,EmailSendReply};
pub mod email_proto {
    tonic::include_proto!("emailsender"); // The string specified here must match the proto package name
}

#[derive(Debug,Clone)]
pub struct EmailGrpcMessenger{
   client: EmailSenderClient<Channel> ,
}

impl EmailGrpcMessenger {
    pub fn new(client: EmailSenderClient<Channel>) -> EmailGrpcMessenger{
        EmailGrpcMessenger{
            client: client 
        }
    }
}
use std::future::Future;
use async_trait::async_trait;
#[async_trait]
impl Messenger for EmailGrpcMessenger {
    async fn send(&mut self,msg:Message)->Result<(),Box<dyn std::error::Error>>{
        let receipients = msg.receipients.join(";");
        let request = Request::new(EmailSendRequest {
            message_id: msg.id,
            email_address: receipients,
            title: msg.topic,
            message:msg.message
        });
        self.client.send_email(request).await.map_err(|e| {
            format!("send email error")
        })?;
        println!("email sent, should get ok");
        Ok(())
 
    }
}

