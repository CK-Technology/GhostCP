// Modal components
use leptos::*;

#[component]
pub fn modal(
    #[prop(into)] title: String,
    #[prop(into)] show: RwSignal<bool>,
    children: Children,
) -> impl IntoView {
    view! {
        <div
            class="modal fade"
            class:show={move || show.get()}
            style:display={move || if show.get() { "block" } else { "none" }}
        >
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{title}</h5>
                        <button
                            type="button"
                            class="btn-close"
                            on:click=move |_| show.set(false)
                        ></button>
                    </div>
                    <div class="modal-body">
                        {children()}
                    </div>
                </div>
            </div>
        </div>
    }
}