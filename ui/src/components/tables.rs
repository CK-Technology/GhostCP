// Table components
use leptos::*;

#[component]
pub fn data_table(children: Children) -> impl IntoView {
    view! {
        <div class="table-responsive">
            <table class="table table-striped">
                {children()}
            </table>
        </div>
    }
}

#[component]
pub fn table_header(children: Children) -> impl IntoView {
    view! {
        <thead>
            <tr>
                {children()}
            </tr>
        </thead>
    }
}

#[component]
pub fn table_body(children: Children) -> impl IntoView {
    view! {
        <tbody>
            {children()}
        </tbody>
    }
}