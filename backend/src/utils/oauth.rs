use oauth2::{
    basic::BasicClient,
    reqwest::async_http_client,
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, RedirectUrl, TokenUrl,
    Scope,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::config::Config;

#[derive(Debug, Clone)]
pub enum OAuthProvider {
    Google,
    GitHub,
    Twitter,
}

impl OAuthProvider {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "google" => Some(OAuthProvider::Google),
            "github" => Some(OAuthProvider::GitHub),
            "twitter" => Some(OAuthProvider::Twitter),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            OAuthProvider::Google => "google",
            OAuthProvider::GitHub => "github",
            OAuthProvider::Twitter => "twitter",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleUserInfo {
    pub id: String,
    pub email: String,
    pub verified_email: bool,
    pub name: String,
    pub picture: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubUserInfo {
    pub id: u64,
    pub login: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwitterUserInfo {
    pub id: String,
    pub username: String,
    pub name: Option<String>,
    pub email: Option<String>,
}

pub struct OAuthClient {
    pub provider: OAuthProvider,
    pub client: BasicClient,
    pub redirect_url: String,
}

impl OAuthClient {
    pub fn new(provider: OAuthProvider, config: &Config, redirect_url: String) -> Option<Self> {
        let (client_id, client_secret, auth_url, token_url) = match provider {
            OAuthProvider::Google => {
                let client_id = config.google_client_id.as_ref()?;
                let client_secret = config.google_client_secret.as_ref()?;
                (
                    client_id.clone(),
                    client_secret.clone(),
                    "https://accounts.google.com/o/oauth2/v2/auth",
                    "https://oauth2.googleapis.com/token",
                )
            }
            OAuthProvider::GitHub => {
                let client_id = config.github_client_id.as_ref()?;
                let client_secret = config.github_client_secret.as_ref()?;
                (
                    client_id.clone(),
                    client_secret.clone(),
                    "https://github.com/login/oauth/authorize",
                    "https://github.com/login/oauth/access_token",
                )
            }
            OAuthProvider::Twitter => {
                let client_id = config.twitter_client_id.as_ref()?;
                let client_secret = config.twitter_client_secret.as_ref()?;
                (
                    client_id.clone(),
                    client_secret.clone(),
                    "https://twitter.com/i/oauth2/authorize",
                    "https://api.twitter.com/2/oauth2/token",
                )
            }
        };

        let client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new(auth_url.to_string()).ok()?,
            Some(TokenUrl::new(token_url.to_string()).ok()?),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_url.clone()).ok()?);

        Some(OAuthClient {
            provider,
            client,
            redirect_url,
        })
    }

    pub fn get_authorize_url(&self) -> (String, String) {
        let mut request = self.client.authorize_url(oauth2::CsrfToken::new_random);

        // Add provider-specific scopes
        match self.provider {
            OAuthProvider::Google => {
                request = request.add_scope(Scope::new("email".to_string()));
                request = request.add_scope(Scope::new("profile".to_string()));
                request = request.add_scope(Scope::new("openid".to_string()));
            }
            OAuthProvider::GitHub => {
                request = request.add_scope(Scope::new("user:email".to_string()));
                request = request.add_scope(Scope::new("read:user".to_string()));
            }
            OAuthProvider::Twitter => {
                request = request.add_scope(Scope::new("tweet.read".to_string()));
                request = request.add_scope(Scope::new("users.read".to_string()));
                request = request.add_scope(Scope::new("offline.access".to_string()));
            }
        }

        let (url, csrf_token) = request.url();
        (url.to_string(), csrf_token.secret().to_string())
    }

    pub async fn exchange_code(&self, code: &str) -> Result<oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>, oauth2::RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>>> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await;

        token_result
    }
}

pub async fn get_google_user_info(access_token: &str) -> Result<GoogleUserInfo, reqwest::Error> {
    let client = Client::new();
    let response = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await?
        .json::<GoogleUserInfo>()
        .await?;

    Ok(response)
}

pub async fn get_github_user_info(access_token: &str) -> Result<GitHubUserInfo, reqwest::Error> {
    let client = Client::new();
    
    // First, get user info
    let response = client
        .get("https://api.github.com/user")
        .bearer_auth(access_token)
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "Toniebee-OAuth")
        .send()
        .await?;
    
    let status = response.status();
    let response_text = response.text().await?;
    
    if !status.is_success() {
        eprintln!("GitHub API error: Status={}, Body={}", status, response_text);
        // Create a reqwest error by making a dummy request that will fail
        // This is a workaround since reqwest::Error doesn't have easy constructors
        let err = Client::new()
            .get("http://[::1]:0") // Invalid URL that will fail
            .send()
            .await;
        return Err(err.unwrap_err());
    }
    
    if response_text.trim().is_empty() {
        eprintln!("GitHub API returned empty response");
        // Similar workaround
        let err = Client::new()
            .get("http://[::1]:0")
            .send()
            .await;
        return Err(err.unwrap_err());
    }
    
    // Debug: log GitHub API response (commented out for production)
    // eprintln!("GitHub API response: {}", response_text);
    
    let mut user_info: GitHubUserInfo = match serde_json::from_str(&response_text) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("Failed to parse GitHub response: {}. Response: {}", e, response_text);
            // Create a reqwest error by making a dummy request
            let err = Client::new()
                .get("http://[::1]:0")
                .send()
                .await;
            return Err(err.unwrap_err());
        }
    };
    
    // If parsing failed, we'd have returned above, so we're good here

    // GitHub email might be private, try to get it from email endpoint
    let email_response = client
        .get("https://api.github.com/user/emails")
        .bearer_auth(access_token)
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await;

    if let Ok(emails_resp) = email_response {
        if let Ok(emails_json) = emails_resp.json::<Vec<serde_json::Value>>().await {
            for email_obj in emails_json {
                if let Some(primary) = email_obj.get("primary").and_then(|v| v.as_bool()) {
                    if primary && email_obj.get("verified").and_then(|v| v.as_bool()).unwrap_or(false) {
                        if let Some(email) = email_obj.get("email").and_then(|v| v.as_str()) {
                            user_info.email = Some(email.to_string());
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(user_info)
}

pub async fn get_twitter_user_info(access_token: &str) -> Result<TwitterUserInfo, reqwest::Error> {
    let client = Client::new();
    let response = client
        .get("https://api.twitter.com/2/users/me")
        .bearer_auth(access_token)
        .query(&[("user.fields", "id,username,name,email")])
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    // Get data field - if missing, return an error
    // We'll handle this by making another request that will fail, or use a simpler approach
    let data = match response.get("data") {
        Some(d) => d,
        None => {
            // Return error by sending a request that will fail
            // This is a workaround since reqwest::Error doesn't have easy constructors
            return Err(Client::new().get("http://[invalid]").build().unwrap_err().into());
        }
    };

    Ok(TwitterUserInfo {
        id: data
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        username: data
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        name: data.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()),
        email: data.get("email").and_then(|v| v.as_str()).map(|s| s.to_string()),
    })
}

