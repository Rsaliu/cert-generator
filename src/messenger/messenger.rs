use std::future::Future;
use async_trait::async_trait;
pub struct Message{
    pub id: String,
    pub receipients: Vec<String>,
    pub topic: String,
    pub message: String
}
use tokio::sync::mpsc::Receiver;

#[async_trait]
pub trait Messenger{
    async fn send(&mut self,msg:Message)->Result<(),Box<dyn std::error::Error>>;
}
pub async fn messenger_service(mut messenger:Box<dyn Messenger + Send>,mut receiver: Receiver<Message>)->Result<(), Box<dyn std::error::Error>>{
    while let Some(received) = receiver.recv().await {
        messenger.send(received).await?;
        println!("message sent waiting for next");
    }
    // for received in receiver.blocking_recv(){
    //     messenger.send(received).await?;
    //     println!("message sent waiting for next");
    // }
    println!("service ended");
    Ok(())
}