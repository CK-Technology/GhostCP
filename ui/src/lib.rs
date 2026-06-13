// GhostCP UI - Modern hosting control panel interface
use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;

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
                <Routes fallback=|| view! { <NotFoundPage/> }>
                    <Route path=path!("/") view=HomePage/>
                    <Route path=path!("/login") view=LoginPage/>
                    <Route path=path!("/dashboard") view=DashboardPage/>

                    // User Management
                    <Route path=path!("/users") view=UsersPage/>
                    <Route path=path!("/users/:id") view=UserDetailPage/>

                    // Web Domains
                    <Route path=path!("/domains") view=DomainsPage/>
                    <Route path=path!("/domains/:id") view=DomainDetailPage/>
                    <Route path=path!("/domains/new") view=NewDomainPage/>

                    // DNS Management
                    <Route path=path!("/dns") view=DnsPage/>
                    <Route path=path!("/dns/:id") view=DnsZoneDetailPage/>
                    <Route path=path!("/dns/new") view=NewDnsZonePage/>

                    // Mail Management
                    <Route path=path!("/mail") view=MailPage/>
                    <Route path=path!("/mail/:id") view=MailDomainDetailPage/>
                    <Route path=path!("/mail/new") view=NewMailDomainPage/>

                    // Database Management
                    <Route path=path!("/databases") view=DatabasesPage/>
                    <Route path=path!("/databases/new") view=NewDatabasePage/>

                    // SSL Certificates
                    <Route path=path!("/ssl") view=SslPage/>
                    <Route path=path!("/ssl/:id") view=SslCertificateDetailPage/>

                    // Cron Jobs
                    <Route path=path!("/cron") view=CronPage/>
                    <Route path=path!("/cron/new") view=NewCronJobPage/>

                    // Backups
                    <Route path=path!("/backups") view=BackupsPage/>
                    <Route path=path!("/backups/new") view=NewBackupConfigPage/>

                    // System Jobs
                    <Route path=path!("/jobs") view=SystemJobsPage/>

                    // Settings
                    <Route path=path!("/settings") view=SettingsPage/>

                    // File Manager (future feature)
                    <Route path=path!("/files") view=FileManagerPage/>

                    // Statistics and Monitoring
                    <Route path=path!("/stats") view=StatsPage/>
                </Routes>
            </Layout>
        </Router>
    }
}

// Hydrate the app for client-side rendering
#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}
