// Table components
use leptos::prelude::*;

#[component]
pub fn DataTable(children: Children) -> impl IntoView {
    view! {
        <div class="table-responsive">
            <table class="table table-striped">
                {children()}
            </table>
        </div>
    }
}

#[component]
pub fn TableHeader(children: Children) -> impl IntoView {
    view! {
        <thead>
            <tr>
                {children()}
            </tr>
        </thead>
    }
}

#[component]
pub fn TableBody(children: Children) -> impl IntoView {
    view! {
        <tbody>
            {children()}
        </tbody>
    }
}
