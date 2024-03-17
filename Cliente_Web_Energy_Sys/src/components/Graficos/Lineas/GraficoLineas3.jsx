import React, { Component } from "react";
import Chart from "react-apexcharts";

class Graficalineas3 extends Component {
  constructor(props) {
    super(props);

    this.state = {
      options: {
        chart: {
          id: "basic-bar",
        },
        xaxis: {
          categories: [1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999],
        },
      },
      series: [
        {
          name: "series-1",
          data: [30, 40, 45, 50, 49, 60, 70, 91],
        },
      ],
    };
  }

  // Método para actualizar los datos del gráfico
  actualizarDatos = () => {
    const newSeries = this.state.series.map((s) => {
      const data = s.data.map(() => {
        return Math.floor(Math.random() * (180 - 20 + 1)) + 20; // Modifica los rangos según tus necesidades
      });
      return { data, name: s.name };
    });

    this.setState({ series: newSeries });
  };

  /*componentDidMount() {
    // Llamar al método actualizarDatos() periódicamente
    this.interval = setInterval(this.actualizarDatos, 2000); // Actualiza cada 5 segundos
  }*/

  componentWillUnmount() {
    // Limpiar el intervalo cuando el componente se desmonte para evitar pérdidas de memoria
    clearInterval(this.interval);
  }

  render() {
    return (
      <div className="graficalineas3">
        <div className="row">
          <div className="mixed-chart">
            <Chart
              options={this.state.options}
              series={this.state.series}
              type="line"
              width="500"
            />
          </div>
        </div>
      </div>
    );
  }
}

export default Graficalineas3;
