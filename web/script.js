window.onload = async function loadbees() {
  var options = await eel.list_bees()();
  var select = document.getElementById("bees").elements["select_bee"];
  for (var i = 0; i < options.length; i++) {
    var opt = options[i];
    var el = document.createElement("option");
    el.textContent = opt;
    el.value = opt;
    select.appendChild(el);
  }
}
