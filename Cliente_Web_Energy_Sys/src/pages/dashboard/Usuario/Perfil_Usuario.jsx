"use client";
import React from "react";
import TituloPagina from "@/components/Titulo/titulopagina";
import Cookies from "universal-cookie";
import { useEffect, useState } from "react";
import Image from "next/image";
import {
  Checkbox,
  Card,
  List,
  ListItem,
  ListItemPrefix,
  Typography,
} from "@material-tailwind/react";

const Perfil_Usuario = () => {
  const cookies = new Cookies();

  //estado para almacenar todo las tareas de x grupo de x usuario
  const [datosuser, setDatosUser] = useState([]);

  useEffect(() => {
    Obtener_Datos_Usuario();
  }, []);

  //Funsion para obtener los datos del usuario
  const Obtener_Datos_Usuario = async () => {
    try {
      const response = await fetch(
        process.env.NEXT_PUBLIC_ACCESLINK +
          "usuario/Datos/" +
          cookies.get("id_user"),
        {
          method: "GET",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
        }
      );

      //console.log(response);
      const data = await response.json();
      console.log(data);
      setDatosUser(data[0]);
      //console.log(datosuser);
    } catch (error) {
      //colocar una alerta de error
      setError(true);
      //console.log(error);
      setMensajeError(error.response.data.error);
    }
  };

  return (
    <div className="mx-auto max-w-242.5">
      <TituloPagina nombrepagina="Perfil Usuario" />
      <div className="overflow-hidden rounded-sm border border-stroke bg-white shadow-default dark:border-strokedark dark:bg-boxdark">
        <div className="relative z-20 h-35 md:h-50">
          <Image
            src={"/img/cover/cover-01.png"}
            alt="profile cover"
            className="h-full w-full rounded-tl-sm rounded-tr-sm object-cover object-center"
            width={970}
            height={260}
            style={{
              width: "auto",
              height: "auto",
            }}
          />
        </div>
        <div className="px-4 pb-6 text-center lg:pb-8 xl:pb-11.5">
          <div className="relative z-30 mx-auto -mt-22 h-30 w-full max-w-30 rounded-full bg-white/20 p-1 backdrop-blur sm:h-44 sm:max-w-44 sm:p-3">
            <div className="relative drop-shadow-2">
              <Image
                src={"/img/user/user-01.png"}
                width={160}
                height={160}
                style={{
                  width: "auto",
                  height: "auto",
                }}
                alt="profile"
              />
            </div>
          </div>
          <div className="mt-1">
            <h2 className="mb-1.5  font-semibold text-black dark:text-white">
              {datosuser.r_nombre_apellidos}
            </h2>
            <h2 className="mb-1.5  font-semibold text-black dark:text-white">
              {datosuser.r_email}
            </h2>
            <div className="flex justify-center">
              <Card className="w-full max-w-[24rem] items-center">
                <List className="flex-row">
                  <ListItem className="p-0">
                    <label
                      htmlFor="horizontal-list-react"
                      className="flex w-full cursor-pointer items-center px-3 py-2"
                    >
                      <ListItemPrefix className="mr-3">
                        <Checkbox
                          id="1"
                          ripple={false}
                          className={`hover:before:opacity-0 ${
                            datosuser.r_configuracion ? 'bg-green-600' : 'bg-red-600'
                          }`}
                          checked={datosuser.r_configuracion}
                          containerProps={{
                            className: "p-0",
                          }}
                          
                        />
                      </ListItemPrefix>
                      <Typography color="blue-gray" className="font-medium">
                        Esta Configurado?
                      </Typography>
                    </label>
                  </ListItem>
                </List>
              </Card>
            </div>
            <div className=" mt-4.5  mx-auto max-w-180">
              <h4 className="font-semibold text-black dark:text-white">
                ¡Bienvenido¡
              </h4>
              <p className="mt-4.5 text-justify">
                ¡Bienvenido al sistema de monitoreo de energía para tu hogar!
                Estamos encantados de tenerte a bordo en este viaje hacia la
                eficiencia energética y el cuidado del medio ambiente. Con
                nuestra plataforma, tendrás el poder de controlar y optimizar el
                consumo de energía en tu hogar, permitiéndote tomar decisiones
                informadas para reducir costos y minimizar tu huella de carbono.
                Desde ahora, tu casa será más inteligente, sostenible y
                conectada que nunca. ¡Comienza a explorar y descubre cómo hacer
                que cada vatio cuente!
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Perfil_Usuario;
