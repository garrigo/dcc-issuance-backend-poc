$("#switch_type").change(function() {
    if ($("#switch_type").val().toString() == 'vaccine') {
        $('#type').val('v');
        // $('#ma_label').val('Marketing authorisation holder:');
        // $('#ma').val('ORG-100030215');
        $('#Mp').show();
        $('#Ma').hide();
        $('#Dn').show();
        $('#Sd').show();
        $('#Dt').show();
        $('#Tt').hide();
        $('#Sc').hide();
        $('#Tr').hide();
        $('#Fr').hide();
        $('#Df').hide();
        $('#Du').hide();  

    }
	else if ($("#switch_type").val().toString() == 'test')
	{
        $('#type').val('t');
        // $('#ma_label').val('Test device identifier:');
        // $('#ma').val('1232');
        $('#Mp').hide();
        $('#Ma').show();
        $('#Dn').hide();
        $('#Sd').hide();
        $('#Dt').hide();
        $('#Tt').show();
        $('#Sc').show();
        $('#Tr').show();
        $('#Fr').hide();
        $('#Df').hide();
        $('#Du').hide(); 
	}
	else{
        $('#type').val('r');
        $('#Mp').hide();
        $('#Ma').hide();
        $('#Dn').hide();
        $('#Sd').hide();
        $('#Dt').hide();
        $('#Tt').hide();
        $('#Sc').hide();
        $('#Tr').hide();
        $('#Fr').show();
        $('#Df').show();
        $('#Du').show();		
	}
    
  });
  
$("#switch_type").trigger("change");

function appendOption(obj_list, select_id) {
  var size = Object.keys(obj_list).length;
  for (i=1; i<=size; i++){
    $(select_id).append($('<option>', {
      value: i,
      text: obj_list[i]["display"]
    }));
  }
}

$( document ).ready(function() {
  $.ajax({
    type: "GET",
    url:  "static/json/disease-agent-targeted.json",
    contentType: "application/json",
    dataType: "json",
    data: JSON.stringify({
        disease: $("#valueSetValues").val()
    }),
    success: function(response) {
        appendOption(response["valueSetValues"], "#tg");
    },
    error: function(response) {
        console.log(response);
    }
  });

  $.ajax({
    type: "GET",
    url:  "static/json/vaccine-medicinal-product.json",
    contentType: "application/json",
    dataType: "json",
    data: JSON.stringify({
        disease: $("#valueSetValues").val()
    }),
    success: function(response) {
        appendOption(response["valueSetValues"], "#mp");
    },
    error: function(response) {
        console.log(response);
    }
  });

  $.ajax({
    type: "GET",
    url:  "static/json/test-used.json",
    contentType: "application/json",
    dataType: "json",
    data: JSON.stringify({
        disease: $("#valueSetValues").val()
    }),
    success: function(response) {
        appendOption(response["valueSetValues"], "#ma");
    },
    error: function(response) {
        console.log(response);
    }
  });
  var date = new Date();
  date.setDate(date.getDate() - 1);
  var yesterdayDate = date.toISOString().substring(0,10);
  var yesterdayTime = date.toISOString().substring(11,16);
  $('#sc').val(yesterdayDate + 'T' + yesterdayTime);
  offset = (new Date().getTimezoneOffset())/-60;
  time_zone = String(offset).padStart(2, '0');
  if(offset >= 0)
    time_zone = "+"+time_zone;
  $('#time_zone').val(time_zone);
});