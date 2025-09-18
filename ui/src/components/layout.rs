use leptos::*;
use leptos_router::*;
use crate::components::navigation::Navigation;
use crate::components::footer::Footer;

#[component]
pub fn Layout(children: Children) -> impl IntoView {
    view! {
        <div class="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors">
            <Navigation/>

            <main class="container mx-auto px-4 py-8">
                {children()}
            </main>

            <Footer/>
        </div>
    }
}

#[component]
pub fn AuthLayout(children: Children) -> impl IntoView {
    view! {
        <div class="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 flex items-center justify-center">
            <div class="max-w-md w-full bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8">
                {children()}
            </div>
        </div>
    }
}

#[component]
pub fn DashboardLayout(children: Children) -> impl IntoView {
    view! {
        <div class="flex min-h-screen bg-gray-50 dark:bg-gray-900">
            // Sidebar
            <aside class="w-64 bg-white dark:bg-gray-800 shadow-lg">
                <div class="p-6">
                    <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
                        "GhostCP"
                    </h1>
                </div>

                <nav class="mt-6">
                    <DashboardSidebar/>
                </nav>
            </aside>

            // Main content
            <div class="flex-1 flex flex-col">
                <header class="bg-white dark:bg-gray-800 shadow-sm p-4">
                    <DashboardHeader/>
                </header>

                <main class="flex-1 p-6">
                    {children()}
                </main>
            </div>
        </div>
    }
}

#[component]
fn DashboardSidebar() -> impl IntoView {
    let navigation_items = vec![
        ("Dashboard", "/dashboard", "M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2 2z"),
        ("Domains", "/domains", "M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"),
        ("DNS", "/dns", "M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547A8.014 8.014 0 004 20v2h16v-2a8.014 8.014 0 00-.572-4.572z"),
        ("Mail", "/mail", "M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"),
        ("Databases", "/databases", "M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"),
        ("SSL", "/ssl", "M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"),
        ("Backups", "/backups", "M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"),
        ("Users", "/users", "M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"),
        ("Jobs", "/jobs", "M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"),
        ("Settings", "/settings", "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"),
    ];

    view! {
        <ul class="space-y-2 px-6">
            {navigation_items.into_iter().map(|(name, path, icon)| {
                view! {
                    <li>
                        <A href=path
                           class="flex items-center px-4 py-2 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                           active_class="bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300">
                            <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d=icon/>
                            </svg>
                            {name}
                        </A>
                    </li>
                }
            }).collect::<Vec<_>>()}
        </ul>
    }
}

#[component]
fn DashboardHeader() -> impl IntoView {
    view! {
        <div class="flex items-center justify-between">
            <div class="flex items-center">
                <h2 class="text-xl font-semibold text-gray-900 dark:text-white">
                    "Dashboard"
                </h2>
            </div>

            <div class="flex items-center space-x-4">
                <button class="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-5 5h5m-5-5v-6a1 1 0 011-1h2a1 1 0 011 1v6m-3-6V7a3 3 0 00-3-3H4a3 3 0 00-3 3v4a3 3 0 003 3h1m0-3h6m4 0h.01"/>
                    </svg>
                </button>

                <div class="relative">
                    <button class="flex items-center text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white">
                        <img class="w-8 h-8 rounded-full mr-2" src="/assets/user-avatar.png" alt="User avatar"/>
                        <span class="text-sm font-medium">"Admin"</span>
                        <svg class="w-4 h-4 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                        </svg>
                    </button>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn PageHeader(title: String, description: Option<String>) -> impl IntoView {
    view! {
        <div class="border-b border-gray-200 pb-5">
            <h1 class="text-3xl font-bold leading-tight tracking-tight text-gray-900">
                {title}
            </h1>
            {description.map(|desc| view! {
                <p class="mt-2 text-sm text-gray-700">{desc}</p>
            })}
        </div>
    }
}

#[component]
pub fn Card(
    #[prop(optional)] title: Option<String>,
    #[prop(optional)] class: Option<String>,
    children: Children,
) -> impl IntoView {
    let class = class.unwrap_or_default();
    
    view! {
        <div class=format!("bg-white overflow-hidden shadow rounded-lg {}", class)>
            {title.map(|t| view! {
                <div class="px-4 py-5 sm:p-6">
                    <h3 class="text-base font-semibold leading-6 text-gray-900">{t}</h3>
                </div>
            })}
            <div class="px-4 py-5 sm:p-6">
                {children()}
            </div>
        </div>
    }
}

#[component]
pub fn LoadingSpinner() -> impl IntoView {
    view! {
        <div class="flex justify-center items-center py-8">
            <svg class="animate-spin -ml-1 mr-3 h-8 w-8 text-blue-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span class="text-gray-600">Loading...</span>
        </div>
    }
}

#[component]
pub fn EmptyState(
    title: String, 
    description: String,
    #[prop(optional)] action: Option<View>
) -> impl IntoView {
    view! {
        <div class="text-center py-12">
            <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path vector-effect="non-scaling-stroke" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 13h6m-3-3v6m-9 1V7a2 2 0 012-2h6l2 2h6a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
            </svg>
            <h3 class="mt-2 text-sm font-semibold text-gray-900">{title}</h3>
            <p class="mt-1 text-sm text-gray-500">{description}</p>
            {action.map(|a| view! {
                <div class="mt-6">
                    {a}
                </div>
            })}
        </div>
    }
}