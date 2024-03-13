--Inicio de la crecion e la BD 17-02-2024

--Proyecto de app distribuidas -- Sistema de Monitoreo de energia en el hogar

--crear la extension para el Universal Unique Identifier
create extension if not exists "uuid-ossp";
--para encriptar datos 
CREATE EXTENSION pgcrypto;
--para verificar si se esta ejecutando el Universal Unique Identifier 
select uuid_generate_v1() as xd;


--Creacion de la tabla de usuarios
CREATE TABLE usuarios(
    iD_User uuid default uuid_generate_V4(),
    nombre_Apellidos VARCHAR(100) not null,
    email VARCHAR(100) not null UNIQUE,
	contra varchar(500) not null,
	uRL_Foto varchar(500) null,
	isAdmin bool Default false not null,
    fecha_creacion TIMESTAMP not NULL DEFAULT now(),
    estado bool Default true not null,
    Primary Key(ID_User)
);

-----Crear tabla para los datos de Energia------

CREATE TABLE data_token(
    tokens uuid default uuid_generate_V4(),
    iD_User uuid not null references usuarios(iD_User) ON DELETE cascade,
    fecha_creacion TIMESTAMP not NULL DEFAULT now(),
    estado bool Default true not null,
    Primary Key(tokens)
);



-----Crear tabla para los datos del consumo de energia de hogar, enviados por ESP32------

CREATE TABLE datos_consumo(
    id_datos_consumo int generated always as identity,
    tokens uuid not null references data_token(tokens) ON DELETE cascade,
    corriente VARCHAR(100) not null,
    voltaje VARCHAR(100) not null,
	potencia varchar(100) not null,
	energia varchar(100)  not null,
	factorpotencia bool Default false not null,
    fecha_creacion TIMESTAMP not NULL DEFAULT now(),
    Primary Key(id_datos_consumo)
);





-------------funcion para iniciar sesion con google--------------

CREATE OR REPLACE FUNCTION public.verification_google(p_email character varying)
 RETURNS TABLE(verification integer, mensaje character varying)
 LANGUAGE plpgsql
AS $function$
declare
	User_Deshabili bool;
	User_Exit bool;
begin
	--Primero Verificar si el correo que se esta ingresando existe
	select into User_Exit case when COUNT(*)>=1 then True else false end  from usuarios where email=p_email;	
	--Segundo  Verificar si el usuario tiene un estado habilitado o deshabilitado
	if (User_Exit) then 
		select into User_Deshabili estado from usuarios where email=p_email;
		if (User_Deshabili) then 
			return query
			select
			cast(case when COUNT(*)>=1 then 1 else 2 end as int),
			 cast(case when COUNT(*)>=1 then 'Login Correcto' else 'Contraseña incorrecta' end as varchar(500))
			from usuarios
			where email  = p_email 
   			and estado=true;
   		else 
   			return query
			select cast(3 as int), cast('Usuario deshabilitado contacte con un administrador' as varchar(500));
		end if;
	else 
	   		return query
			select cast(4 as int), cast('Este correo no esta registrado' as varchar(500));
	end if;
end;
$function$
;


select * from usuarios 
select verification_google('jveram10@uteq.edu.ec');

--crear procedimineto almacenado para iniciar sesion con cuenta local de la base de datos
CREATE OR REPLACE FUNCTION public.verification_auth(p_email character varying, p_contra character varying)
 RETURNS TABLE(verification integer, mensaje character varying)
 LANGUAGE plpgsql
AS $function$
declare
	User_Deshabili bool;
	User_Exit bool;
begin
	--Primero Verificar si el correo que se esta ingresando existe
	select into User_Exit case when COUNT(*)>=1 then True else false end  from usuarios where email=p_email;		
	--Segundo  Verificar si el usuario tiene un estado habilitado o deshabilitado
	if (User_Exit) then 
		select into User_Deshabili estado from usuarios where email=p_email;
		if (User_Deshabili) then 
			return query
			select
			cast(case when COUNT(*)>=1 then 1 else 2 end as int),
			 cast(case when COUNT(*)>=1 then 'Login Correcto' else 'Contraseña incorrecta' end as varchar(500))
			from usuarios
			where email  = p_email
			and  PGP_SYM_DECRYPT(contra ::bytea, 'SGDV_KEY') = p_contra
   			and estado=true;
   		else 
   			return query
			select cast(3 as int), cast('Usuario deshabilitado contacte con un administrador' as varchar(500));
		end if;
	else 
	   		return query
			select cast(4 as int), cast('Este correo no esta registrado' as varchar(500));
	end if;
end;
$function$
;

select verification_auth('jveram10@uteq.edu.ec', 'john123');

-----------Procedimiento almacenado para crear usuarios de la APP----------------
drop procedure crear_usuario

CREATE OR REPLACE PROCEDURE public.sp_crear_usuario(
		IN p_nombres_apellidos character varying,
		IN p_email character varying,
		IN p_contra character varying
		)
LANGUAGE plpgsql
AS $procedure$

Begin
	insert into usuarios(
						nombre_apellidos,
						email,
						contra
						)values
						(
						p_nombres_apellidos,
						p_email,
						PGP_SYM_ENCRYPT(p_contra::text,'SGDV_KEY')
						);

COMMIT;
END;
$procedure$
;

call sp_crear_usuario('John Vera','jveram10@uteq.edu.ec','john123');

select * from usuarios u 

--delete from usuarios


--crear procedimineto almacenado para iniciar sesion con cuenta local de la base de datos
CREATE OR REPLACE FUNCTION public.fu_verification_auth(p_email character varying, contra1 character varying)
 RETURNS TABLE(verification integer, mensaje character varying)
 LANGUAGE plpgsql
AS $function$
declare
	User_Deshabili bool;
	User_Exit bool;
begin
	--Primero Verificar si el correo que se esta ingresando existe
	select into User_Exit case when COUNT(*)>=1 then True else false end  from usuarios where email=p_email;	
	--Segundo  Verificar si el usuario tiene un estado habilitado o deshabilitado
	if (User_Exit) then 
		select into User_Deshabili estado from usuarios where email=p_email;
		if (User_Deshabili) then 
			return query
			select
			cast(case when COUNT(*)>=1 then 1 else 2 end as int),
			 cast(case when COUNT(*)>=1 then 'Login Correcto' else 'Contraseña incorrecta' end as varchar(500))
			from usuarios
			where email  = p_email 
			and  PGP_SYM_DECRYPT(contra ::bytea, 'SGDV_KEY') = contra1
   			and estado=true;
   		else 
   			return query
			select cast(3 as int), cast('Usuario deshabilitado contacte con un administrador' as varchar(500));
		end if;
	else 
	   		return query
			select cast(4 as int), cast('Este correo no esta registrado' as varchar(500));
	end if;
end;
$function$
;

select * from fu_verification_auth('jveram10@uteq.edu.ec','john123')



---------funcion que devuelve los datos del usuario------------

CREATE OR REPLACE FUNCTION public.fu_auth_data(p_email character varying)
 RETURNS TABLE(userc character varying)
 LANGUAGE plpgsql
AS $function$
begin
	return query
	select cast(iD_User as varchar(500)) as userp  from usuarios where email  = p_email;
end;
$function$
;


select fu_auth_data('jveram10@uteq.edu.ec');


--Triger para validar el registro de usuarios

CREATE OR REPLACE FUNCTION public.fu_tr_registrar_usuario()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
begin
	if trim(new.nombre_apellidos) = '' then
            raise exception 'Nombres y Apellidos';
    end if;
   	if trim(new.email) = '' then
            raise exception 'El correo';
    end if;
   
   	IF trim(new.contra) = '' THEN
    RAISE EXCEPTION 'La contraseña';
	end if;
   
return new;
end
$function$
;

--trigger para insertar asociado a la funcion
create trigger tr_registrar_usuario
before insert 
on usuarios
for each row 
execute function fu_tr_registrar_usuario();


select nombre_apellidos , PGP_SYM_DECRYPT(contra ::bytea, 'SGDV_KEY')  from usuarios u 

--delete  from usuarios where nombre_apellidos = 'Flixpi Music'

--call sp_crear_usuario('Flixpi Music','pruebaprimera098@gmail.com','');



-----------


--select email , nombre_apellidos from usuarios where cast(iD_User as varchar(500)) = p_id_user;







