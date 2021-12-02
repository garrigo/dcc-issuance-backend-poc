$("#switch_field").change(function() {
    if ($("#switch_field").val().toString() == 'vaccine') {
        $('#type').val('v');
        $('#Mp').show();
        $('#Ma').show();
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
	else if ($("#switch_field").val().toString() == 'test')
	{
        $('#type').val('t');
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
  
$("#switch_field").trigger("change");

$( document ).ready(function() {

});