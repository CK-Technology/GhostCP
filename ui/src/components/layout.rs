use leptos::*;
use leptos_router::*;
use crate::components::navigation::Sidebar;

#[component]
pub fn Layout(children: Children) -> impl IntoView {
    view! {
        <div class="min-h-screen bg-gray-50">
            <Sidebar />
            
            <div class="lg:pl-64">
                <main class="py-10">
                    <div class="px-4 sm:px-6 lg:px-8">
                        {children()}
                    </div>
                </main>
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