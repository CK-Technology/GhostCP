// Form components
use leptos::prelude::*;

#[component]
pub fn FormGroup(children: Children) -> impl IntoView {
    view! {
        <div class="form-group">
            {children()}
        </div>
    }
}

#[component]
pub fn TextInput(
    #[prop(into)] label: String,
    #[prop(into)] name: String,
    value: RwSignal<String>,
    #[prop(optional)] placeholder: Option<String>,
    #[prop(optional)] required: bool,
) -> impl IntoView {
    let input_id = name.clone();
    view! {
        <div class="mb-3">
            <label for=input_id.clone() class="form-label">{label}</label>
            <input
                type="text"
                class="form-control"
                id=input_id
                name=name
                placeholder=placeholder.unwrap_or_default()
                required=required
                prop:value=move || value.get()
                on:input=move |ev| {
                    value.set(event_target_value(&ev));
                }
            />
        </div>
    }
}
