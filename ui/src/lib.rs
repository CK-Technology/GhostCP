// GhostCP UI - Modern hosting control panel interface
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

pub mod components;
pub mod pages;
pub mod api;
pub mod auth;
pub mod types;
pub mod utils;

use components::layout::Layout;
use pages::*;

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/ghostcp-ui.css"/>
        <Title text="GhostCP - Modern Hosting Control Panel"/>
        <Meta name="description" content="GhostCP - A modern, Rust-powered hosting control panel built with Leptos"/>
        <Meta name="viewport" content="width=device-width, initial-scale=1"/>
        
        <Router>
            <Layout>
                <Routes>
                    <Route path="/" view=HomePage/>
                    <Route path="/login" view=LoginPage/>
                    <Route path="/dashboard" view=DashboardPage/>
                    
                    // User Management
                    <Route path="/users" view=UsersPage/>
                    <Route path="/users/:id" view=UserDetailPage/>
                    
                    // Web Domains
                    <Route path="/domains" view=DomainsPage/>
                    <Route path="/domains/:id" view=DomainDetailPage/>
                    <Route path="/domains/new" view=NewDomainPage/>
                    
                    // DNS Management
                    <Route path="/dns" view=DnsPage/>
                    <Route path="/dns/:id" view=DnsZoneDetailPage/>
                    <Route path="/dns/new" view=NewDnsZonePage/>
                    
                    // Mail Management
                    <Route path="/mail" view=MailPage/>
                    <Route path="/mail/:id" view=MailDomainDetailPage/>
                    <Route path="/mail/new" view=NewMailDomainPage/>
                    
                    // Database Management
                    <Route path="/databases" view=DatabasesPage/>
                    <Route path="/databases/new" view=NewDatabasePage/>
                    
                    // SSL Certificates
                    <Route path="/ssl" view=SslPage/>
                    <Route path="/ssl/:id" view=SslCertificateDetailPage/>
                    
                    // Cron Jobs
                    <Route path="/cron" view=CronPage/>
                    <Route path="/cron/new" view=NewCronJobPage/>
                    
                    // Backups
                    <Route path="/backups" view=BackupsPage/>
                    <Route path="/backups/new" view=NewBackupConfigPage/>
                    
                    // System Jobs
                    <Route path="/jobs" view=SystemJobsPage/>
                    
                    // Settings
                    <Route path="/settings" view=SettingsPage/>
                    
                    // File Manager (future feature)
                    <Route path="/files" view=FileManagerPage/>
                    
                    // Statistics and Monitoring
                    <Route path="/stats" view=StatsPage/>
                    
                    // 404 fallback
                    <Route path="/*any" view=NotFoundPage/>
                </Routes>
            </Layout>
        </Router>
    }
}

// Hydrate the app for client-side rendering
#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use wasm_bindgen::prelude::wasm_bindgen;
    console_error_panic_hook::set_once();
    leptos::mount_to_body(App);
}