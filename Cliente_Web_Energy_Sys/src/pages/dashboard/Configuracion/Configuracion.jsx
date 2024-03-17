"use client";
import React from "react";
import TituloPagina from "@/components/Titulo/titulopagina";
import Cookies from "universal-cookie";
import { useEffect, useState } from "react";
import Image from "next/image";
import { FaGear } from "react-icons/fa6";
import { FaCopy } from "react-icons/fa";
import {
  Checkbox,
  Card,
  List,
  ListItem,
  ListItemPrefix,
  Typography,
  Button,
  CardBody,
} from "@material-tailwind/react";

const TABLE_HEAD = ["Token", "Fecha Creación", "Copiar"];

const Configuracion = () => {
  const cookies = new Cookies();

  // Estado para indicar si se ha copiado el token
  const [copiedToken, setCopiedToken] = useState(null);

  // Estado para almacenar la lista de token
  const [token, setToken] = useState([]);

  //Ejecuta una vez para cargar las tareas al cargar el componente
  useEffect(() => {
    ListarToken(); // función para obtener las tareas
  }, []);

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
      //console.log(data);
      setDatosUser(data[0]);
      //console.log(datosuser);
    } catch (error) {
      //colocar una alerta de error
      //console.log(error);
      setMensajeError(error.response.data.error);
    }
  };

  //funcion para listar el token creado
  const ListarToken = async () => {
    try {
      const response = await fetch(
        process.env.NEXT_PUBLIC_ACCESLINK +
          "usuario/Token/" +
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
      setToken(data);
      //console.log(datosuser);
    } catch (error) {
      //colocar una alerta de error
      //console.log(error);
      setMensajeError(error.response.data.error);
    }
  };

  // Función para copiar el token al portapapeles
  const copyTokenToClipboard = (token) => {
    // Copiar el token al portapapeles
    navigator.clipboard.writeText(token);
    // Actualizar el estado para mostrar que se ha copiado
    setCopiedToken(token);
    // Después de 2 segundos, restablecer el estado para eliminar el indicador de copia
    alert("Token copiado al portapapeles: " + token);
    setTimeout(() => {
      setCopiedToken(null);
    }, 2000);
  };

  return (
    <div className="mx-auto max-w-242.5">
      <TituloPagina nombrepagina="Configuración" />
      <div className="overflow-hidden rounded-sm border border-stroke bg-white shadow-default dark:border-strokedark dark:bg-boxdark">
        <div className="px-4 pb-10 pt-10 text-center lg:pb-8 xl:pb-11.5">
          <div className="mt-1">
            <div className=" mt-4.5  mx-auto max-w-180">
              <h2 className=" text-title-md2  text-black dark:text-white">
                Generar un Token
              </h2>
              <p className="mt-4.5 text-justify">
                "Para acceder a los datos en la aplicación web, primero debe
                generar un token de autenticación aquí. Luego, este token debe
                ser configurado en la aplicación móvil para poder mostrar los
                datos aqui."
              </p>
            </div>
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
                            datosuser.r_configuracion
                              ? "bg-green-600"
                              : "bg-red-600"
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
            <div className="flex justify-center pt-10">
              <Button className="flex items-center gap-3 bg-green-700 ">
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                  strokeWidth={2}
                  stroke="currentColor"
                  className="h-5 w-5"
                >
                  <FaGear size={22} />
                </svg>
                Generar Token
              </Button>
            </div>
            <CardBody className="overflow-scroll px-0">
              {token.length === 0 ? (
                <div className=" items-center text-center">
                  <Typography variant="h5">
                    No hay actividades registradas.
                  </Typography>
                  <Typography variant="h5">Cree actividades</Typography>
                </div>
              ) : (
                <table className="mt-4 w-full min-w-max table-auto text-left">
                  <thead>
                    <tr>
                      {TABLE_HEAD.map((head) => (
                        <th
                          key={head}
                          className="border-y border-blue-gray-100 bg-blue-gray-50/50 p-4"
                        >
                          <Typography
                            variant="small"
                            color="blue-gray"
                            className="font-normal leading-none opacity-70"
                          >
                            {head}
                          </Typography>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {token.map((task) => (
                      <tr key={task.r_tokens}>
                        <td className="p-4 border-b border-blue-gray-50">
                          <Typography
                            variant="small"
                            color="blue-gray"
                            className="font-normal"
                          >
                            {task.r_tokens}
                          </Typography>
                        </td>
                        <td className="p-4 border-b border-blue-gray-50">
                          <Typography
                            variant="small"
                            color="blue-gray"
                            className="font-normal"
                          >
                            {task.r_fecha_creacion}
                          </Typography>
                        </td>
                        <td className="p-4 border-b border-blue-gray-50">
                          <Button
                            onClick={() => copyTokenToClipboard(task.r_tokens)}
                            color="indigo"
                            buttonType="filled"
                            size="regular"
                            rounded={false}
                            block={false}
                            iconOnly={false}
                            ripple="light"
                          >
                            <FaCopy className="mr-2" />
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </CardBody>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Configuracion;
