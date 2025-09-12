use leptos::*;
use crate::components::layout::{PageHeader, Card};

#[component]
pub fn DashboardPage() -> impl IntoView {
    // TODO: Fetch real data from API
    let stats = create_resource(
        || (),
        |_| async move {
            // Simulate API call
            gloo_timers::future::TimeoutFuture::new(500).await;
            
            DashboardStats {
                domains: 15,
                dns_zones: 8,
                mail_domains: 5,
                databases: 12,
                ssl_certificates: 10,
                active_jobs: 2,
            }
        }
    );
    
    view! {
        <div class="space-y-8">
            <PageHeader 
                title="Dashboard".to_string() 
                description=Some("Overview of your hosting environment".to_string())
            />
            
            <div class="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
                <Suspense fallback=move || view! { <StatsCardSkeleton /> }>
                    {move || {
                        stats.get().map(|s| view! {
                            <StatsCard 
                                title="Web Domains".to_string()
                                value=s.domains
                                href="/domains"
                                icon="globe"
                            />
                            <StatsCard 
                                title="DNS Zones".to_string()
                                value=s.dns_zones
                                href="/dns"
                                icon="server"
                            />
                            <StatsCard 
                                title="Mail Domains".to_string()
                                value=s.mail_domains
                                href="/mail"
                                icon="mail"
                            />
                            <StatsCard 
                                title="Databases".to_string()
                                value=s.databases
                                href="/databases"
                                icon="database"
                            />
                            <StatsCard 
                                title="SSL Certificates".to_string()
                                value=s.ssl_certificates
                                href="/ssl"
                                icon="shield"
                            />
                            <StatsCard 
                                title="Active Jobs".to_string()
                                value=s.active_jobs
                                href="/jobs"
                                icon="cog"
                            />
                        })
                    }}
                </Suspense>
            </div>
            
            <div class="grid grid-cols-1 gap-8 lg:grid-cols-2">
                <RecentActivity />
                <SystemStatus />
            </div>
        </div>
    }
}

#[derive(Clone)]
struct DashboardStats {
    domains: u32,
    dns_zones: u32,
    mail_domains: u32,
    databases: u32,
    ssl_certificates: u32,
    active_jobs: u32,
}

#[component]
fn StatsCard(title: String, value: u32, href: &'static str, icon: &'static str) -> impl IntoView {
    view! {
        <Card class="hover:shadow-lg transition-shadow">
            <a href=href class="block">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <StatsIcon name=icon />
                    </div>
                    <div class="ml-5 w-0 flex-1">
                        <dl>
                            <dt class="text-sm font-medium text-gray-500 truncate">
                                {title}
                            </dt>
                            <dd class="text-3xl font-semibold text-gray-900">
                                {value}
                            </dd>
                        </dl>
                    </div>
                </div>
            </a>
        </Card>
    }
}

#[component]
fn StatsCardSkeleton() -> impl IntoView {
    view! {
        <Card>
            <div class="animate-pulse">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <div class="h-8 w-8 bg-gray-200 rounded"></div>
                    </div>
                    <div class="ml-5 w-0 flex-1">
                        <div class="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
                        <div class="h-8 bg-gray-200 rounded w-1/2"></div>
                    </div>
                </div>
            </div>
        </Card>
    }
}

#[component]
fn StatsIcon(name: &'static str) -> impl IntoView {
    let (bg_class, text_class) = match name {
        "globe" => ("bg-blue-500", "text-blue-500"),
        "server" => ("bg-green-500", "text-green-500"),
        "mail" => ("bg-yellow-500", "text-yellow-500"),
        "database" => ("bg-purple-500", "text-purple-500"),
        "shield" => ("bg-red-500", "text-red-500"),
        "cog" => ("bg-gray-500", "text-gray-500"),
        _ => ("bg-gray-500", "text-gray-500"),
    };
    
    view! {
        <div class=format!("flex items-center justify-center h-8 w-8 rounded-md {}", bg_class)>
            <svg class=format!("h-5 w-5 text-white") fill="none" viewBox="0 0 24 24" stroke="currentColor">
                {match name {
                    "globe" => view! {
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3s-4.5 4.03-4.5 9 2.015 9 4.5 9zm0 0c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3s4.5 4.03 4.5 9-2.015 9-4.5 9zm-9-9h18" />
                    },
                    "server" => view! {
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21.75 17.25v-.228a4.5 4.5 0 00-.12-1.03l-2.268-9.64a3.375 3.375 0 00-3.285-2.602H7.923a3.375 3.375 0 00-3.285 2.602l-2.268 9.64a4.5 4.5 0 00-.12 1.03v.228m0 0A3 3 0 005.25 21h13.5A3 3 0 0021.75 17.25zM9 12.75h6m-6 3h6" />
                    },
                    "mail" => view! {
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
                    },
                    "database" => view! {
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 0v3.75m-16.5-3.75v3.75m16.5 0v3.75C20.25 16.153 16.556 18 12 18s-8.25-1.847-8.25-4.125v-3.75m16.5 0c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" />
                    },
                    "shield" => view! {
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                    },
                    "cog" => view! {
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.343 3.94c.09-.542.56-.94 1.11-.94h1.093c.55 0 1.02.398 1.11.94l.149.894c.07.424.384.764.78.93.398.164.855.142 1.205-.108l.737-.527a1.125 1.125 0 011.45.12l.773.774c.39.389.44 1.002.12 1.45l-.527.737c-.25.35-.272.806-.107 1.204.165.397.505.71.93.78l.893.15c.543.09.94.56.94 1.109v1.094c0 .55-.397 1.02-.94 1.11l-.893.149c-.425.07-.765.383-.93.78-.165.398-.143.854.107 1.204l.527.738c.32.447.27 1.06-.12 1.45l-.774.773a1.125 1.125 0 01-1.449.12l-.738-.527c-.35-.25-.806-.272-1.203-.107-.397.165-.71.505-.781.929l-.149.894c-.09.542-.56.94-1.11.94h-1.094c-.55 0-1.019-.398-1.11-.94l-.148-.894c-.071-.424-.384-.764-.781-.93-.398-.164-.854-.142-1.204.108l-.738.527c-.447.32-1.06.269-1.45-.12l-.773-.774a1.125 1.125 0 01-.12-1.45l.527-.737c.25-.35.273-.806.108-1.204-.165-.397-.505-.71-.93-.78l-.894-.15c-.542-.09-.94-.56-.94-1.109v-1.094c0-.55.398-1.02.94-1.11l.894-.149c.424-.07.765-.383.93-.78.165-.398.143-.854-.107-1.204l-.527-.738a1.125 1.125 0 01.12-1.45l.773-.773a1.125 1.125 0 011.45-.12l.737.527c.35.25.807.272 1.204.107.397-.165.71-.505.78-.929l.15-.894z M13.5 12a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z" />
                    },
                    _ => view! { <rect width="24" height="24" fill="currentColor" /> },
                }}
            </svg>
        </div>
    }
}

#[component]
fn RecentActivity() -> impl IntoView {
    view! {
        <Card title=Some("Recent Activity".to_string())>
            <div class="flow-root">
                <ul class="-mb-8">
                    <ActivityItem 
                        title="SSL certificate renewed"
                        description="example.com"
                        time="2 hours ago"
                        icon="shield"
                        color="green"
                    />
                    <ActivityItem 
                        title="New domain added"
                        description="newsite.com"
                        time="1 day ago"
                        icon="globe"
                        color="blue"
                    />
                    <ActivityItem 
                        title="DNS zone updated"
                        description="example.com"
                        time="2 days ago"
                        icon="server"
                        color="yellow"
                    />
                </ul>
            </div>
        </Card>
    }
}

#[component]
fn ActivityItem(title: &'static str, description: &'static str, time: &'static str, icon: &'static str, color: &'static str) -> impl IntoView {
    let icon_class = format!("text-{}-500", color);
    let bg_class = format!("bg-{}-50", color);
    
    view! {
        <li>
            <div class="relative pb-8">
                <div class="relative flex space-x-3">
                    <div>
                        <span class=format!("h-8 w-8 rounded-full {} flex items-center justify-center ring-8 ring-white", bg_class)>
                            <svg class=format!("h-5 w-5 {}", icon_class) fill="currentColor" viewBox="0 0 20 20">
                                <circle cx="10" cy="10" r="3"/>
                            </svg>
                        </span>
                    </div>
                    <div class="flex min-w-0 flex-1 justify-between space-x-4 pt-1.5">
                        <div>
                            <p class="text-sm text-gray-900">{title}</p>
                            <p class="text-sm text-gray-500">{description}</p>
                        </div>
                        <div class="whitespace-nowrap text-right text-sm text-gray-500">
                            {time}
                        </div>
                    </div>
                </div>
            </div>
        </li>
    }
}

#[component]
fn SystemStatus() -> impl IntoView {
    view! {
        <Card title=Some("System Status".to_string())>
            <div class="space-y-6">
                <StatusItem 
                    name="CPU Usage"
                    value="45%"
                    status="good"
                />
                <StatusItem 
                    name="Memory Usage"
                    value="72%"
                    status="warning"
                />
                <StatusItem 
                    name="Disk Usage"
                    value="38%"
                    status="good"
                />
                <StatusItem 
                    name="Load Average"
                    value="1.2"
                    status="good"
                />
            </div>
        </Card>
    }
}

#[component]
fn StatusItem(name: &'static str, value: &'static str, status: &'static str) -> impl IntoView {
    let (color_class, bg_class) = match status {
        "good" => ("text-green-800 bg-green-100", "bg-green-200"),
        "warning" => ("text-yellow-800 bg-yellow-100", "bg-yellow-200"),
        "error" => ("text-red-800 bg-red-100", "bg-red-200"),
        _ => ("text-gray-800 bg-gray-100", "bg-gray-200"),
    };
    
    view! {
        <div class="flex items-center justify-between">
            <div class="text-sm font-medium text-gray-900">{name}</div>
            <div class=format!("inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {}", color_class)>
                {value}
            </div>
        </div>
    }
}