"use client";
import { Card, Input, Button, Typography } from "@material-tailwind/react";
import axios from "axios";
import Lottie from "lottie-react";
import { Dialog_Error, Loader } from "../widgets";
import Cookies from "universal-cookie";
import anim from "../../public/anim/HomeLogin.json";
import { useState, useEffect } from "react";
import { useGoogleLogin } from "@react-oauth/google";
import Router from "next/router";

export default function Index() {
  //Borrar cookies en caso de existir alguna
  useEffect(() => {
    const cookies = new Cookies();
    cookies.remove("id_user");
    cookies.remove("myTokenName");
  }, []);
  //variables para el inicio de sesion
  const [user, setUser] = useState({
    p_email: "",
    p_contra: "",
  });

  //variables para el registrar un usuario
  const [re_user, setRe_user] = useState({
    p_nombres_apellidos: "",
    p_email: "",
    p_contra: " ",
    p_contra2: " ",
  });

  //variable para detectar un error y mostrar el error
  const [error, setError] = useState(false);

  //variable para almacenar el mensaje del error
  const [mensajeError, setMensajeError] = useState("");

  //variable para mostrar el loader cuando carga una peticion
  const [load, setLoader] = useState(false);

  //variable para detectar si quiere Registrarse
  const [registrarse, setRegistrarse] = useState(false);

  //variable para saber si se inicio sesion correctamente
  const [autenticado, setAutencidado] = useState(false);

  //funcion para alimentar la variable que contiene las credenciales
  const HandleChange = (e) => {
    setUser({ ...user, [e.target.name]: e.target.value });
  };

  //funcion para alimentar la variable que contiene las credenciales para registrarse
  const HandleChangeRegis = (e) => {
    setRe_user({ ...re_user, [e.target.name]: e.target.value });
  };

  //funcion para logear y redirigir al menu principal
  const InicioSesion = async (e) => {
    e.preventDefault();
    setLoader(true);
    try {
      const result = await axios.post(
        process.env.NEXT_PUBLIC_ACCESLINK + "auth/Login",
        user,
        {
          withCredentials: true,
        }
      );

      const cookies = new Cookies();
      //Cookie para el token
      cookies.set("myTokenName", result.data.token, { path: "/" }); //enviar cokiee y almacenarla
      //Cookie para el id del usuario
      cookies.set("id_user", result.data.id, { path: "/" });

      //console.log(result.data);
      
      //para abrir la nueva ruta en la misma pestana
      Router.push("/dashboard/Home");
    } catch (error) {
      console.log(error);
      setLoader(false);
      //colocar una alerta de error cuando no se pueda inciar sesion
      setError(true);
      setMensajeError(error.response.data.error);
    }
  };

  //Envento clik para iniciar con google

  const login = useGoogleLogin({
    onSuccess: async (respose) => {
      try {
        const res = await axios.get(
          "https://www.googleapis.com/oauth2/v3/userinfo",
          {
            headers: {
              Authorization: `Bearer ${respose.access_token}`,
            },
          }
        );

        //console.log(res.data);
        //Aqui va para sacar el token ty sacar el mail del token que te regresa google
        const email = res.data.email;
        //console.log(email);

        //Llama al metodo pasandole el email
        GoogleLogin(email);
      } catch (error) {
        console.log(error);
      }
    },
  });

  const GoogleLogin = async (p_email) => {
    setLoader(true);
    try {
      //console.log(p_email);
      const result = await axios.post(
        process.env.NEXT_PUBLIC_ACCESLINK + "auth/LoginGoogle",
        { p_email },
        {
          withCredentials: true,
        }
      );
      //console.log("asdas", result);

      const cookies = new Cookies();
      //Cookie para el token
      cookies.set("myTokenName", result.data.token, { path: "/" }); //enviar cokiee y almacenarla
      //Cookie para el id del usuario
      cookies.set("id_user", result.data.id, { path: "/" });

      
      //para abrir la nueva ruta en la misma pestana
      Router.push("/dashboard/Home");

      //console.log(result.data);
    } catch (error) {
      console.log(error);
      setLoader(false);
      //colocar una alerta de error cuando no se pueda inciar sesion
      setError(true);
      setMensajeError(error.response.data.error);
    }
  };

  //funcion para cerrar el dialog del error
  const cerrar = (valor) => {
    setError(valor);
  };

  //funcion para abrir el ard de registrarse
  const condi_Registrare = (valor) => {
    // No actualices el estado si el valor es el mismo
    if (valor !== registrarse) {
      setRegistrarse(valor);
    }
  };

  //funcion para registrar un usario y redirigir al menu principal
  const Registrarse = async (e) => {
    e.preventDefault();
    if (re_user.p_contra != re_user.p_contra2) {
      setMensajeError("Las contraseñas no son iguales");
      setError(true);
    } else {
      setLoader(true);
      try {
        const result = await axios.post(
          process.env.NEXT_PUBLIC_ACCESLINK + "auth/RegistrarUser",
          re_user,
          {
            withCredentials: true,
          }
        );

        setLoader(false);
        //para abrir la nueva ruta en la misma pestana

        setRe_user({
          p_nombres_apellidos: "",
          p_email: "",
        });

        condi_Registrare(!registrarse);
      } catch (error) {
        console.log(error);
        setLoader(false);
        //colocar una alerta de error cuando no se pueda inciar sesion
        setError(true);
        if(error.response.data.error == "llave duplicada viola restricción de unicidad «usuarios_email_key»"){
            setMensajeError("Correo ya registrado, por favor ingrese otro o inicie sesión");
        }else{
            setMensajeError(error.response.data.error);
        }
      }
    }
  };

  //Envento clik para registrarse con google

  const registraseGoogle = useGoogleLogin({
    onSuccess: async (respose) => {
      try {
        const res = await axios.get(
          "https://www.googleapis.com/oauth2/v3/userinfo",
          {
            headers: {
              Authorization: `Bearer ${respose.access_token}`,
            },
          }
        );

        //console.log(res.data);
        //Aqui va para sacar el token ty sacar el mail del token que te regresa google
        const email = res.data.email;
        const name = res.data.name;
        // Actualizar el estado con los datos del usuario de Google
        setRe_user({
          p_nombres_apellidos: res.data.name,
          p_email: res.data.email,
        });
      } catch (error) {
        console.log(error);
      }
    },
  });

  return (
    <div className=" w-full h-ful ">
      {load ? <Loader /> : ""}
      {error ? (
        <Dialog_Error
          mensaje={mensajeError}
          titulo="Error Inicio de sesion"
          cerrar={cerrar}
        />
      ) : (
        ""
      )}
      {registrarse ? (
        <Card
          color="transparent"
          shadow={false}
          className="mx-auto w-full max-w-[24rem] mt-10 shadow-xl p-6 hover:shadow-green-500 border-4 border-blue-900  border-solid text-center bg-white items-center justify-center rounded-none"
        >
          <div className="p-2 mx-auto">
            <Typography variant="h4" color="blue-gray">
              Monitoreo Electrico en el Hogar
            </Typography>
            <Lottie animationData={anim} className="w-20 mx-auto" />
          </div>
          <Typography variant="h4" color="blue-gray">
            Registrarse
          </Typography>
          <form className="mt-8 mb-2" onSubmit={Registrarse}>
            <div className="mb-1 flex flex-col gap-6">
              <Input
                type="text"
                label="Nombre y Apellido"
                size="lg"
                name="p_nombres_apellidos"
                value={re_user.p_nombres_apellidos} // Utilizar el nombre del usuario de Google
                onChange={HandleChangeRegis}
                readOnly
              />
              <Input
                variant="outlined"
                label="Correo"
                size="lg"
                name="p_email"
                value={re_user.p_email} // Utilizar el correo electrónico del usuario de Google
                onChange={HandleChangeRegis}
                readOnly
              />
              <Input
                onChange={HandleChangeRegis}
                type="password"
                name="p_contra"
                label="Contraseña"
                size="lg"
                placeholder="********"
              />
              <Input
                onChange={HandleChangeRegis}
                type="password"
                name="p_contra2"
                label="Repita la Contraseña"
                size="lg"
                placeholder="********"
              />
            </div>

            {re_user.p_email != null && re_user.p_email !== "" && (
              <Button
                className="mt-4 bg-light-green-900 font-bold "
                type="submit"
                fullWidth
              >
                Registrarse
              </Button>
            )}

            <div
              className="h-auto bg-gray-200  flex items-center justify-center mt-4 cursor-pointer text-center rounded-lg mx-auto border-2 border-green-900  border-solid"
              onClick={registraseGoogle}
            >
              <div className="p-2">
                <img
                  className="h-7 w-7 rounded-full"
                  src="/img/Home/Google.png"
                  alt="User image"
                />
              </div>
              <div className="ml-2 p-3 pr-10 font-bold text-blue-gray-600">
                Registrarse con Google
              </div>
            </div>
            <div className="h-auto bg-gray-200  flex items-center justify-center mt-4 cursor-pointer text-center rounded-lg mx-auto">
              <div className="mt-6 text-center">
                Ya tiene una cuenta?{" "}
                <div
                  onClick={() => condi_Registrare(!registrarse)}
                  className="text-primary"
                >
                  Inicia Sesión
                </div>
              </div>
            </div>
          </form>
        </Card>
      ) : (
        <Card
          color="transparent"
          shadow={false}
          className="mx-auto w-full max-w-[24rem] mt-10 shadow-xl p-6 hover:shadow-green-500 border-4 border-blue-900  border-solid text-center bg-white items-center justify-center rounded-none"
        >
          <div className="p-2 mx-auto">
            <Typography variant="h4" color="blue-gray">
              Monitoreo Electrico en el Hogar
            </Typography>
            <Lottie animationData={anim} className="w-20 mx-auto" />
          </div>
          <Typography variant="h4" color="blue-gray">
            Iniciar Sesion
          </Typography>
          <form className="mt-8 mb-2" onSubmit={InicioSesion}>
            <div className="mb-1 flex flex-col gap-6">
              <Input
                variant="outlined"
                label="Correo"
                size="lg"
                name="p_email"
                onChange={HandleChange}
              />
              <Input
                onChange={HandleChange}
                type="password"
                name="p_contra"
                label="Contraseña"
                size="lg"
                placeholder="********"
              />
            </div>

            <Button
              className="mt-6 bg-light-green-900 font-bold "
              type="submit"
              fullWidth
            >
              Iniciar Sesión
            </Button>
            <div
              className="h-auto bg-gray-200  flex items-center justify-center mt-4 cursor-pointer text-center rounded-lg mx-auto border-2 border-green-900  border-solid"
              onClick={login}
            >
              <div className="p-2">
                <img
                  className="h-7 w-7 rounded-full"
                  src="/img/Home/Google.png"
                  alt="User image"
                />
              </div>
              <div className="ml-2 p-3 pr-10 font-bold text-blue-gray-600">
                Continuar con Google
              </div>
            </div>
            <div className="h-auto bg-gray-200  flex items-center justify-center mt-4 cursor-pointer text-center rounded-lg mx-auto">
              <div className="mt-6 text-center">
                No tienes una cuenta?{" "}
                <div
                  onClick={() => condi_Registrare(!registrarse)}
                  className="text-primary"
                >
                  Registrate
                </div>
              </div>
            </div>
          </form>
        </Card>
      )}
    </div>
  );
}
