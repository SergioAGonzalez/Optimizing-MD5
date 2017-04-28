`timescale 1ns / 1ps

module test();

	reg clk_t, reset_t, msg_in_valid_t;
	reg[0:7] msg_in_width_t;
	reg[0:127] msg_in_t;
	wire msg_out_valid_t, ready_t;
	wire[0:127] msg_out_t;
	
	pancham test_pancham(clk_t, reset_t, msg_in_t, msg_in_width_t, msg_in_valid_t , msg_out_t, msg_out_valid_t, ready_t);
	
	
	
	initial begin
		clk_t <= 0;
		reset_t <= 0;
		//message 'Hashed' -> 48 61 73 68 65 64
		msg_in_t <= 128'h646568736148;
		msg_in_width_t <= 8'h48;
		msg_in_valid_t <= 0;
		#4 reset_t <= 1;
		#4 reset_t <= 0;
		#4 msg_in_valid_t <= 1;
	end
	
	always
		#1 clk_t <= ~clk_t;

endmodule 