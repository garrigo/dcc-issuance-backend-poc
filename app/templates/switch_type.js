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

$( document ).ready(function() {
  var date = new Date();
  date.setDate(date.getDate() - 1);
  var yesterday = date.toJSON().slice(0,10);
  $('#sc').val(yesterday+"T23:59");
  offset = (new Date().getTimezoneOffset())/-60;
  time_zone = String(offset).padStart(2, '0');
  if(offset >= 0)
    time_zone = "+"+time_zone;
  $('#time_zone').val(time_zone);
});