//! Download utilities - Equivalent to curl/wget commands

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tokio::io::AsyncWriteExt;

/// Download type
pub enum DownloadType {
    Binary,
    Text,
    Service,
}

/// Downloader with progress
pub struct Downloader {
    client: reqwest::Client,
}

impl Downloader {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        
        Self { client }
    }
    
    /// Download file - Equivalent to curl/wget
    pub async fn download(&self, url: &str, destination: &str, dtype: DownloadType) -> Result<()> {
        let response = self.client.get(url)
            .send()
            .await
            .with_context(|| format!("Failed to download {}", url))?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to download {}: HTTP {}", 
                url, 
                response.status()
            ));
        }
        
        let total_size = response.content_length().unwrap_or(0);
        
        // Create progress bar for binaries
        let pb = if matches!(dtype, DownloadType::Binary) && total_size > 0 {
            let pb = ProgressBar::new(total_size);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            Some(pb)
        } else {
            None
        };
        
        let mut file = tokio::fs::File::create(destination)
            .await
            .with_context(|| format!("Failed to create file: {}", destination))?;
        
        let mut downloaded: u64 = 0;
        let mut stream = response.bytes_stream();
        
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("Failed to read chunk")?;
            file.write_all(&chunk).await?;
            
            downloaded += chunk.len() as u64;
            if let Some(pb) = &pb {
                pb.set_position(downloaded);
            }
        }
        
        if let Some(pb) = pb {
            pb.finish_with_message("Download complete");
        }
        
        Ok(())
    }
    
    /// Download with fallback - Try multiple URLs
    pub async fn download_with_fallback(
        &self,
        urls: &[String],
        destination: &str,
        dtype: DownloadType,
    ) -> Result<()> {
        let mut last_error = None;
        
        for url in urls {
            match self.download(url, destination, dtype.clone()).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("All download attempts failed")))
    }
}
