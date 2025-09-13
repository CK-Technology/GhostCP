// Notification components
use leptos::*;

#[component]
pub fn alert(
    #[prop(into)] message: String,
    #[prop(into, optional)] alert_type: String,
    #[prop(optional)] dismissible: bool,
) -> impl IntoView {
    let (show, set_show) = create_signal(true);
    let alert_class = format!("alert alert-{}", if alert_type.is_empty() { "info".to_string() } else { alert_type });

    view! {
        <div class={alert_class} class:show={move || show.get()} style:display={move || if show.get() { "block" } else { "none" }}>
            {message}
            {dismissible.then(|| view! {
                <button
                    type="button"
                    class="btn-close"
                    on:click=move |_| set_show.set(false)
                ></button>
            })}
        </div>
    }
}

#[component]
pub fn toast(
    #[prop(into)] title: String,
    #[prop(into)] message: String,
    #[prop(into)] show: RwSignal<bool>,
) -> impl IntoView {
    view! {
        <div
            class="toast"
            class:show={move || show.get()}
        >
            <div class="toast-header">
                <strong class="me-auto">{title}</strong>
                <button
                    type="button"
                    class="btn-close"
                    on:click=move |_| show.set(false)
                ></button>
            </div>
            <div class="toast-body">
                {message}
            </div>
        </div>
    }
}