// Card components
use leptos::*;

#[component]
pub fn card(
    #[prop(optional)] title: Option<String>,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="card">
            {title.map(|t| view! {
                <div class="card-header">
                    <h5 class="card-title">{t}</h5>
                </div>
            })}
            <div class="card-body">
                {children()}
            </div>
        </div>
    }
}

#[component]
pub fn stat_card(
    #[prop(into)] title: String,
    #[prop(into)] value: String,
    #[prop(optional)] icon: Option<String>,
) -> impl IntoView {
    view! {
        <div class="card text-center">
            <div class="card-body">
                {icon.map(|i| view! {
                    <i class={format!("fa fa-{} fa-2x mb-2", i)}></i>
                })}
                <h5 class="card-title">{title}</h5>
                <p class="card-text h3">{value}</p>
            </div>
        </div>
    }
}