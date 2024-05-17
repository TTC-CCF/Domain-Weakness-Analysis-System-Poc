function analyze() {
    let domain_name = $('#domain-name-input').val();

    window.location.href = '/analysis?name=' + domain_name;
}