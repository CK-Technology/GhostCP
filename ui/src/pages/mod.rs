// Page components
use leptos::*;
use leptos_router::*;
use crate::components::layout::{PageHeader, Card, LoadingSpinner, EmptyState};

pub mod auth;
pub mod dashboard;
pub mod domains;
pub mod dns;
pub mod mail;
pub mod databases;
pub mod ssl;
pub mod cron;
pub mod backups;
pub mod users;
pub mod jobs;
pub mod settings;
pub mod files;
pub mod stats;

// Re-export page components
pub use auth::*;
pub use dashboard::*;
pub use domains::*;
pub use dns::*;
pub use mail::*;
pub use databases::*;
pub use ssl::*;
pub use cron::*;
pub use backups::*;
pub use users::*;
pub use jobs::*;
pub use settings::*;
pub use files::*;
pub use stats::*;

#[component]
pub fn HomePage() -> impl IntoView {
    let navigate = use_navigate();
    
    // Redirect to dashboard if authenticated, otherwise to login
    create_effect(move |_| {
        // TODO: Check authentication status
        navigate("/login", Default::default()).ok();
    });
    
    view! {
        <div class="min-h-screen bg-gray-900 flex items-center justify-center">
            <div class="text-center">
                <h1 class="text-4xl font-bold text-white mb-4">
                    "Welcome to GhostCP"
                </h1>
                <p class="text-gray-300 mb-8">
                    "A modern, Rust-powered hosting control panel"
                </p>
                <div class="space-x-4">
                    <a href="/login" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-md font-medium">
                        "Get Started"
                    </a>
                    <a href="https://github.com/ghostcp/ghostcp" target="_blank" class="bg-gray-800 hover:bg-gray-700 text-white px-6 py-3 rounded-md font-medium">
                        "View Source"
                    </a>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn NotFoundPage() -> impl IntoView {
    view! {
        <div class="min-h-screen bg-gray-50 flex items-center justify-center">
            <div class="text-center">
                <h1 class="text-6xl font-bold text-gray-900 mb-4">"404"</h1>
                <h2 class="text-2xl font-semibold text-gray-700 mb-4">
                    "Page not found"
                </h2>
                <p class="text-gray-500 mb-8">
                    "The page you're looking for doesn't exist."
                </p>
                <a href="/dashboard" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-md font-medium">
                    "Go to Dashboard"
                </a>
            </div>
        </div>
    }
}