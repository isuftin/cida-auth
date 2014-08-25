create or replace trigger AUTH_TOKEN_ID_TRG 
	before insert on AUTH_TOKEN 
	for each row 
	begin
		select seq_auth_token_id.nextval into :new.id from dual;
	end;