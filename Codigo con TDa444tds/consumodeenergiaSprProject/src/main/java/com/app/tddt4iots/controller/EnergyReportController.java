package com.app.tddt4iots.controller;

import com.app.tddt4iots.entities.EnergyReport;
import com.app.tddt4iots.repository.EnergyReportRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/energyreport")
public class EnergyReportController {

    @Autowired
    private EnergyReportRepository energyreportRepository;

    @GetMapping
    public ResponseEntity<List<EnergyReport>> getEnergyReport() {
        List<EnergyReport> listEnergyReport = energyreportRepository.findAll();
        return ResponseEntity.ok(listEnergyReport);
    }

    @PostMapping
    public ResponseEntity<EnergyReport> insertEnergyReport(@RequestBody EnergyReport energyreport) {
        EnergyReport newEnergyReport = energyreportRepository.save(energyreport);
        return ResponseEntity.ok(newEnergyReport);
    }

    @PutMapping
    public ResponseEntity<EnergyReport> updateEnergyReport(@RequestBody EnergyReport energyreport) {
        EnergyReport upEnergyReport = energyreportRepository.save(energyreport);
        if (upEnergyReport != null) {
            return ResponseEntity.ok(upEnergyReport);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping(value = "{id}")
    public ResponseEntity<EnergyReport> deletePersons(@PathVariable("id") Long consumptionData) {
        energyreportRepository.deleteById(consumptionData);
        return ResponseEntity.ok(null);
    }

}
