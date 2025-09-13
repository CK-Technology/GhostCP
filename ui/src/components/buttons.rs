// Button components
use leptos::*;

#[component]
pub fn primary_button(
    #[prop(into)] text: String,
    #[prop(optional)] onclick: Option<Box<dyn Fn() + 'static>>,
    #[prop(optional)] disabled: bool,
) -> impl IntoView {
    view! {
        <button
            type="button"
            class="btn btn-primary"
            disabled={disabled}
            on:click=move |_| {
                if let Some(ref handler) = onclick {
                    handler();
                }
            }
        >
            {text}
        </button>
    }
}

#[component]
pub fn danger_button(
    #[prop(into)] text: String,
    #[prop(optional)] onclick: Option<Box<dyn Fn() + 'static>>,
    #[prop(optional)] disabled: bool,
) -> impl IntoView {
    view! {
        <button
            type="button"
            class="btn btn-danger"
            disabled={disabled}
            on:click=move |_| {
                if let Some(ref handler) = onclick {
                    handler();
                }
            }
        >
            {text}
        </button>
    }
}