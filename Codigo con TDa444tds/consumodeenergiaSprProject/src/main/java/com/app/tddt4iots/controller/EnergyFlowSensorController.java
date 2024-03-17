package com.app.tddt4iots.controller;

import com.app.tddt4iots.entities.EnergyFlowSensor;
import com.app.tddt4iots.repository.EnergyFlowSensorRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/energyflowsensor")
public class EnergyFlowSensorController {

    @Autowired
    private EnergyFlowSensorRepository energyflowsensorRepository;

    @GetMapping
    public ResponseEntity<List<EnergyFlowSensor>> getEnergyFlowSensor() {
        List<EnergyFlowSensor> listEnergyFlowSensor = energyflowsensorRepository.findAll();
        return ResponseEntity.ok(listEnergyFlowSensor);
    }

    @PostMapping
    public ResponseEntity<EnergyFlowSensor> insertEnergyFlowSensor(@RequestBody EnergyFlowSensor energyflowsensor) {
        EnergyFlowSensor newEnergyFlowSensor = energyflowsensorRepository.save(energyflowsensor);
        return ResponseEntity.ok(newEnergyFlowSensor);
    }

    @PutMapping
    public ResponseEntity<EnergyFlowSensor> updateEnergyFlowSensor(@RequestBody EnergyFlowSensor energyflowsensor) {
        EnergyFlowSensor upEnergyFlowSensor = energyflowsensorRepository.save(energyflowsensor);
        if (upEnergyFlowSensor != null) {
            return ResponseEntity.ok(upEnergyFlowSensor);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping(value = "{id}")
    public ResponseEntity<EnergyFlowSensor> deletePersons(@PathVariable("id") Long currentFlowRate) {
        energyflowsensorRepository.deleteById(currentFlowRate);
        return ResponseEntity.ok(null);
    }

}
