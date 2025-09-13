// Form components
use leptos::*;

#[component]
pub fn form_group(children: Children) -> impl IntoView {
    view! {
        <div class="form-group">
            {children()}
        </div>
    }
}

#[component]
pub fn text_input(
    #[prop(into)] label: String,
    #[prop(into)] name: String,
    #[prop(into)] value: RwSignal<String>,
    #[prop(optional)] placeholder: Option<String>,
    #[prop(optional)] required: bool,
) -> impl IntoView {
    view! {
        <div class="mb-3">
            <label for={name.clone()} class="form-label">{label}</label>
            <input
                type="text"
                class="form-control"
                id={name.clone()}
                name={name}
                placeholder={placeholder.unwrap_or_default()}
                required={required}
                prop:value={move || value.get()}
                on:input=move |ev| {
                    value.set(event_target_value(&ev));
                }
            />
        </div>
    }
}